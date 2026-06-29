use std::{collections::HashMap, path::PathBuf};

use fxprof_processed_profile::{
    Category, CategoryColor, CategoryHandle, CpuDelta, FrameAddress, FrameFlags, LibraryHandle,
    LibraryInfo, ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval, ThreadHandle,
    Timestamp,
    debugid::DebugId,
    symbol_info::{AddressFrame, AddressInfo, LibSymbolInfo, ProfileSymbolInfo, SymbolStringTable},
};
use regex::Regex;
use wholesym::{LookupAddress, SymbolManager, SymbolManagerConfig};

#[derive(Default)]
struct StackFrame<'a> {
    address: u64,
    symbol: Option<&'a str>,
    symbol_offset: Option<u64>,
    source: &'a str,
}

impl StackFrame<'_> {
    pub fn parse<'a>(mut line: &'a str) -> Option<StackFrame<'a>> {
        line = line.trim();
        if line.is_empty() {
            return None;
        }

        let open_paren = line.rfind('(')?;
        let close_paren = line.rfind(')')?;
        if open_paren >= close_paren {
            return None;
        }

        let source = &line[open_paren + 1..close_paren];
        let remaining = line[..open_paren].trim_end();
        let first_space = remaining.find(' ')?;
        let address = u64::from_str_radix(&remaining[..first_space], 16).ok()?;
        let middle = remaining[first_space + 1..].trim();

        let mut symbol = Some(middle);
        let mut offset = None;

        if middle == "[unknown]" {
            symbol = None;
        } else {
            let re_offset = Regex::new(r"\+0x([A-Fa-f0-9]+)$").unwrap();
            if let Some(caps) = re_offset.captures(middle) {
                let cap_match = caps.get(0).unwrap();
                let offset_str = caps.get(1).unwrap().as_str();

                offset = u64::from_str_radix(offset_str, 16).ok();

                let sym_end = middle.len() - cap_match.as_str().len();
                symbol = Some(middle[..sym_end].trim_end());
            }
        }

        Some(StackFrame {
            address,
            symbol,
            symbol_offset: offset,
            source,
        })
    }

    pub fn choose_category(&self, rdata: &RuntimeData) -> CategoryHandle {
        if self.address >= 0x8000_0000_0000_0000 || self.source == "[kernel.kallsyms]" {
            return rdata.kernel_category;
        }

        eprintln!("gd_dir: {}, source: {}", rdata.gd_dir, self.source);
        if !self.source.starts_with(&rdata.gd_dir) {
            return rdata.system_category;
        }

        // TODO: somehow get tuliphook jit?

        rdata.user_category
    }
}

struct Sample<'a> {
    thread: ThreadHandle,
    timestamp: Timestamp,
    raw_timestamp: f64,
    sample_num: u64,
    frames: Vec<StackFrame<'a>>,
}

#[derive(Debug)]
struct PerfHeader<'a> {
    thread: &'a str,
    pid: u32,
    tid: u32,
    timestamp: f64,
    sample_number: u64,
    event: &'a str,
}

impl PerfHeader<'_> {
    fn parse(line: &str) -> Option<PerfHeader<'_>> {
        let re = Regex::new(r"^(.*?)\s+(\d+)/(\d+)\s+(\d+\.\d+):\s+(\d+)\s+([^:]+):\s*$").unwrap();

        let caps = re.captures(line)?;

        Some(PerfHeader {
            thread: caps.get(1)?.as_str(),
            pid: caps.get(2)?.as_str().parse().ok()?,
            tid: caps.get(3)?.as_str().parse().ok()?,
            timestamp: caps.get(4)?.as_str().parse().ok()?,
            sample_number: caps.get(5)?.as_str().parse().ok()?,
            event: caps.get(6)?.as_str(),
        })
    }
}

struct RuntimeData {
    profile: Profile,
    process: ProcessHandle,
    pid: u32,
    ms_per_sample: f64,
    user_category: CategoryHandle,
    system_category: CategoryHandle,
    kernel_category: CategoryHandle,
    gd_dir: String,
}

impl RuntimeData {
    pub fn populate_libraries(&mut self) {
        let meta_data = std::fs::read_to_string(format!("/tmp/perf-{}.meta.txt", self.pid))
            .expect("failed to read meta.txt");

        let mut libs = HashMap::new();

        let mut at_maps = false;
        for line in meta_data.lines() {
            if line.starts_with("Modules") || line.is_empty() {
                continue;
            }

            if line.starts_with("Maps") {
                at_maps = true;
                continue;
            }

            if !at_maps {
                let (_, path) = line.split_once(' ').unwrap();
                let name = PathBuf::from(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();

                let lib = self.profile.add_lib(LibraryInfo {
                    name: name.clone(),
                    debug_name: name.clone(),
                    path: path.to_string(),
                    debug_path: String::new(),
                    debug_id: DebugId::nil(),
                    code_id: None,
                    arch: Some("x86_64".to_string()),
                });
                libs.insert(path.to_string(), lib);
            } else {
                let (start_end, path) = line.rsplit_once(' ').unwrap();
                let (start, end) = start_end.split_once(' ').unwrap();

                let start = u64::from_str_radix(start, 16).unwrap();
                let end = u64::from_str_radix(end, 16).unwrap();
                let Some(lib) = libs.get(path) else {
                    continue;
                };

                self.profile
                    .add_lib_mapping(self.process, *lib, start, end, 0);
            }
        }
    }

    pub async fn symbolicate(mut self) -> anyhow::Result<Self> {
        let modules: Vec<(LibraryHandle, std::collections::BTreeSet<u32>)> =
            self.profile.native_frame_addresses_per_library();

        let mut profile_symbols = ProfileSymbolInfo {
            string_table: SymbolStringTable::new(),
            lib_symbols: Vec::new(),
        };

        for (lib, addrs) in modules {
            let manager = SymbolManager::with_config(SymbolManagerConfig::default());
            let info = self.profile.get_library_info(lib);

            let symbol_map = match manager
                .load_symbol_map_for_binary_at_path(&PathBuf::from(&info.path), None)
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("failed to load symbol map for {}: {e}", info.path);
                    continue;
                }
            };

            let mut lib_symbol_info = LibSymbolInfo {
                lib_handle: lib,
                sorted_addresses: Vec::new(),
                address_infos: Vec::new(),
            };
            for addr in addrs {
                if let Some(si) = symbol_map.lookup(LookupAddress::Relative(addr)).await {
                    lib_symbol_info.sorted_addresses.push(addr);

                    let mut frames = Vec::new();
                    if let Some(dbf) = si.frames {
                        for fdi in dbf {
                            frames.push(AddressFrame {
                                function_name: profile_symbols
                                    .string_table
                                    .index_for_string(&fdi.function.unwrap_or_default()),
                                file: fdi.file_path.map(|p| {
                                    profile_symbols.string_table.index_for_string(p.raw_path())
                                }),
                                col: None,
                                line: fdi.line_number,
                                function_start_col: None,
                                function_start_line: None,
                            });
                        }
                    }

                    lib_symbol_info.address_infos.push(AddressInfo {
                        symbol_name: profile_symbols
                            .string_table
                            .index_for_string(&si.symbol.name),
                        symbol_start_address: si.symbol.address,
                        symbol_size: si.symbol.size,
                        frames,
                    });
                }
            }

            profile_symbols.lib_symbols.push(lib_symbol_info);
        }

        self.profile = self.profile.make_symbolicated_profile(&profile_symbols);
        self.profile.set_symbolicated(true);

        Ok(self)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    args.next().unwrap();
    let script_path = args.next().unwrap();
    let pid = args.next().unwrap().parse::<u32>()?;
    let frequency = args.next().unwrap().parse::<u32>()?;
    let gd_exe = args.next().unwrap();
    let start_time_unix = args.next().unwrap().parse::<u64>()?;

    let script_data = std::fs::read_to_string(script_path)?;

    let (first_line, _) = script_data.split_once('\n').unwrap();

    // how many milliseconds have passed since the system booted up until the first sample
    let first_sample_rel_ms = first_line
        .split_whitespace()
        .nth(2)
        .unwrap()
        .trim_end_matches(':')
        .parse::<f64>()?
        * 1000.0;

    // (approx) time of the first sample in ms since unix epoch
    // each next sample is calculated as first_sample_unix + (sample_time_ms - first_sample_rel_ms)
    let first_sample_unix = start_time_unix as f64;

    let cvt_time = |sample_time_s: f64| {
        Timestamp::from_millis_since_reference(sample_time_s * 1000.0 - first_sample_rel_ms)
    };

    let mut profile = Profile::new(
        "Geometry Dash",
        ReferenceTimestamp::from_millis_since_unix_epoch(first_sample_unix),
        SamplingInterval::from_hz(frequency as f32),
    );
    let process = profile.add_process(
        "GeometryDash.exe",
        pid,
        Timestamp::from_millis_since_reference(0.0),
    );

    let user_category = profile.handle_for_category(Category("User", CategoryColor::Yellow));
    let system_category = profile.handle_for_category(Category("System", CategoryColor::Orange));
    let kernel_category = profile.handle_for_category(Category("Kernel", CategoryColor::LightRed));
    let mut rtdata = RuntimeData {
        profile,
        process,
        pid,
        ms_per_sample: 1000.0 / frequency as f64,
        user_category,
        system_category,
        kernel_category,
        gd_dir: PathBuf::from(gd_exe)
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    };
    rtdata.populate_libraries();

    let mut threads = HashMap::new();

    let mut sample = None;

    for (i, line) in script_data.lines().enumerate() {
        if line.is_empty() {
            commit_sample(&mut rtdata, sample.take());
            continue;
        }

        // if there is no active sample and this line isnt empty, it must be a sample
        if sample.is_none() {
            let perf_header = PerfHeader::parse(line);
            let Some(header) = perf_header else {
                panic!("expected sample header at line {}", i + 1);
            };

            let thread = *threads.entry(header.tid).or_insert_with(|| {
                let thr = rtdata.profile.add_thread(
                    process,
                    header.tid,
                    cvt_time(header.timestamp),
                    header.tid == pid,
                );
                rtdata.profile.set_thread_name(thr, header.thread);
                thr
            });

            sample = Some(Sample {
                thread,
                timestamp: cvt_time(header.timestamp),
                raw_timestamp: header.timestamp,
                sample_num: header.sample_number,
                frames: Vec::new(),
            });

            continue;
        }

        // stack frame
        let frame = match StackFrame::parse(line) {
            Some(f) => f,
            None => {
                panic!("line {}: failed to parse stack frame: {}", i + 1, line);
            }
        };

        sample.as_mut().unwrap().frames.push(frame);
    }

    commit_sample(&mut rtdata, sample.take());

    let rtdata = rtdata.symbolicate().await?;

    serde_json::to_writer(std::io::stdout(), &rtdata.profile)?;

    Ok(())
}

fn commit_sample(rdata: &mut RuntimeData, s: Option<Sample<'_>>) {
    let Some(s) = s else {
        return;
    };

    let mut cur_node = None;

    for frame in s.frames.into_iter().rev() {
        let category = frame.choose_category(rdata);

        let frame_handle = rdata.profile.handle_for_frame_with_address(
            if category == rdata.kernel_category {
                FrameAddress::KernelInstructionPointer(frame.address)
            } else {
                FrameAddress::InstructionPointer(rdata.process, frame.address)
            },
            category,
            FrameFlags::empty(),
        );

        cur_node = Some(rdata.profile.handle_for_stack(frame_handle, cur_node));
    }

    let cpu_delta = CpuDelta::from_millis(rdata.ms_per_sample);

    rdata
        .profile
        .add_sample(s.thread, s.timestamp, cur_node, cpu_delta, 1);
}
