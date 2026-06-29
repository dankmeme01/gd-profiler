#![feature(duration_millis_float)]

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::Duration,
};

use fxprof_processed_profile::{
    Category, CategoryColor, CategoryHandle, CounterHandle, CpuDelta, FrameAddress, FrameFlags,
    GraphColor, LibraryHandle, LibraryInfo, ProcessHandle, Profile, ReferenceTimestamp,
    SamplingInterval, ThreadHandle, Timestamp,
    debugid::DebugId,
    symbol_info::{AddressFrame, AddressInfo, LibSymbolInfo, ProfileSymbolInfo, SymbolStringTable},
};
use regex::Regex;
use wholesym::{FrameDebugInfo, LookupAddress, SymbolManager, SymbolManagerConfig, SymbolMap};

#[derive(Default)]
struct StackFrame<'a> {
    address: u64,
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

        Some(StackFrame { address, source })
    }

    pub fn choose_category(&self, rdata: &RuntimeData) -> CategoryHandle {
        if self.address >= 0x8000_0000_0000_0000 || self.source == "[kernel.kallsyms]" {
            return rdata.kernel_category;
        }

        let Some(library) = rdata.lookup_address(self.address) else {
            // eprintln!("lookup failed for {:x}", self.address);
            return rdata.other_category;
        };

        let info = rdata.profile.get_library_info(library);
        let library_path = PathBuf::from(&info.path);
        let library_name = library_path.file_name().unwrap().to_string_lossy();
        let (base_name, _) = library_name.rsplit_once('.').unwrap();

        if library_name.ends_with(".exe") {
            return rdata.gd_category;
        }

        if library_name == "libcocos2d.dll" || library_name == "libExtensions.dll" {
            return rdata.cocos_category;
        }

        if library_name == "Geode.dll" {
            return rdata.mods_category;
        }

        if info.path.contains("geode/unzipped")
            && library_path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                == base_name
        {
            // this is a mod dll
            return rdata.mods_category;
        }

        if self.source.ends_with(".map") {
            // user library
            rdata.user_category
        } else {
            // system wine dll
            rdata.system_category
        }
    }
}

struct Sample<'a> {
    thread: ThreadHandle,
    timestamp: Timestamp,
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

#[derive(Clone)]
struct StoredLibrary {
    handle: LibraryHandle,
    base_address: u64,
    size: u64,
}

#[derive(Clone, Default)]
struct PerfMeta {
    modules: Vec<(u64, String)>,
    maps: Vec<(u64, u64, String)>,
    memory: Vec<(f64, u64, u64)>,
}

impl PerfMeta {
    pub fn parse(data: &str) -> anyhow::Result<PerfMeta> {
        let mut meta = PerfMeta::default();
        let mut lines = data.lines();

        // modules
        for line in lines.by_ref() {
            if line == "Maps:" {
                break;
            } else if line == "Modules:" || line.is_empty() {
                continue;
            }

            let (address, filepath) = line
                .split_once(' ')
                .ok_or_else(|| anyhow::anyhow!("failed to parse module line: {}", line))?;

            let address = u64::from_str_radix(address, 16)?;
            meta.modules.push((address, filepath.to_string()));
        }

        // maps
        for line in lines.by_ref() {
            if line == "Memory:" {
                break;
            } else if line.is_empty() {
                continue;
            }

            let (start_end, filepath) = line
                .rsplit_once(' ')
                .ok_or_else(|| anyhow::anyhow!("failed to parse map line: {}", line))?;

            let (start, end) = start_end
                .split_once(' ')
                .ok_or_else(|| anyhow::anyhow!("failed to parse map line: {}", line))?;

            let start = u64::from_str_radix(start, 16)?;
            let end = u64::from_str_radix(end, 16)?;
            meta.maps.push((start, end, filepath.to_string()));
        }

        // memory
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let parts = line.split(' ').collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(anyhow::anyhow!("failed to parse memory line: {}", line));
            }

            let timestamp = parts[0].parse::<f64>()?;
            let heap_total = parts[1].parse::<u64>()?;
            let total = parts[2].parse::<u64>()?;

            meta.memory.push((timestamp, heap_total, total));
        }

        Ok(meta)
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
    gd_category: CategoryHandle,
    cocos_category: CategoryHandle,
    mods_category: CategoryHandle,
    other_category: CategoryHandle,
    meta: PerfMeta,
    memory_counter: CounterHandle,
    heap_counter: CounterHandle,

    libs: HashMap<String, StoredLibrary>,
    libs_sorted: BTreeMap<u64, StoredLibrary>,
    symbol_manager: SymbolManager,
    gd_dir: String,
}

impl RuntimeData {
    pub fn new(
        mut profile: Profile,
        process: ProcessHandle,
        pid: u32,
        ms_per_sample: f64,
        gd_dir: String,
    ) -> Self {
        let user_category = profile.handle_for_category(Category("User", CategoryColor::Yellow));
        let system_category =
            profile.handle_for_category(Category("System", CategoryColor::Orange));
        let kernel_category = profile.handle_for_category(Category("Kernel", CategoryColor::Red));
        let gd_category =
            profile.handle_for_category(Category("Geometry Dash", CategoryColor::LightBlue));
        let cocos_category =
            profile.handle_for_category(Category("cocos2d-x", CategoryColor::Blue));
        let mods_category =
            profile.handle_for_category(Category("Geode Mods", CategoryColor::Purple));
        let other_category = profile.handle_for_category(Category::OTHER);

        let memory_counter = profile.add_counter(process, "Total memory", "memory", "Total memory");
        profile.set_counter_color(memory_counter, GraphColor::Orange);
        let heap_counter = profile.add_counter(process, "Heap memory", "memory", "Heap memory");
        profile.set_counter_color(heap_counter, GraphColor::Yellow);

        let meta_data = std::fs::read_to_string(format!("/tmp/perf-{}.meta.txt", pid))
            .expect("failed to read meta.txt");
        let meta = PerfMeta::parse(&meta_data).expect("failed to parse meta.txt");

        Self {
            profile,
            process,
            pid,
            ms_per_sample,
            user_category,
            system_category,
            kernel_category,
            gd_category,
            cocos_category,
            mods_category,
            other_category,
            meta,
            memory_counter,
            heap_counter,
            libs: HashMap::new(),
            libs_sorted: BTreeMap::new(),
            symbol_manager: SymbolManager::with_config(SymbolManagerConfig::default()),
            gd_dir,
        }
    }

    pub fn initialize(&mut self) {
        for (address, path) in &self.meta.modules {
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

            let library = StoredLibrary {
                handle: lib,
                base_address: *address,
                size: 0,
            };
            self.libs.insert(path.to_string(), library.clone());
            self.libs_sorted.insert(*address, library);
        }

        for (start, end, path) in &self.meta.maps {
            let Some(lib) = self.libs.get_mut(path) else {
                continue;
            };
            let Some(sorted_lib) = self.libs_sorted.get_mut(&lib.base_address) else {
                continue;
            };

            self.profile.add_lib_mapping(
                self.process,
                lib.handle,
                *start,
                *end,
                (start - lib.base_address) as u32,
            );
            lib.size = lib.size.max(end - lib.base_address);
            sorted_lib.size = lib.size;
        }

        let mut last_heap = 0.0;
        let mut last_total = 0.0;
        for &(rel_timestamp, heap_bytes, total_bytes) in &self.meta.memory {
            let time = Timestamp::from_millis_since_reference(
                Duration::from_secs_f64(rel_timestamp).as_millis_f64(),
            );
            let total_bytes = total_bytes as f64;
            let heap_bytes = heap_bytes as f64;

            eprintln!(
                "delta: {} {}",
                total_bytes - last_total,
                heap_bytes - last_heap
            );
            self.profile
                .add_counter_sample(self.memory_counter, time, total_bytes, 1);
            self.profile
                .add_counter_sample(self.heap_counter, time, heap_bytes, 1);

            last_heap = heap_bytes;
            last_total = total_bytes;
        }
    }

    pub fn lookup_address(&self, address: u64) -> Option<LibraryHandle> {
        let (_, lib) = self.libs_sorted.range(..=address).next_back()?;

        if address >= lib.base_address + lib.size {
            return None;
        }

        Some(lib.handle)
    }

    pub async fn symbolicate(mut self) -> anyhow::Result<Self> {
        let modules = self.profile.native_frame_addresses_per_library();

        let mut profile_symbols = ProfileSymbolInfo {
            string_table: SymbolStringTable::new(),
            lib_symbols: Vec::new(),
        };

        for (lib, addrs) in modules {
            let info = self.profile.get_library_info(lib);

            let symbol_map = match self
                .symbol_manager
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

                    // TODO this is a bit buggy, im not sure how to use it correctly
                    // might be due to lbr messing things up

                    // let frames = si
                    //     .frames
                    //     .as_ref()
                    //     .map(|frames| {
                    //         frames
                    //             .iter()
                    //             .flat_map(|fdi| {
                    //                 convert_address_frame(
                    //                     fdi,
                    //                     &mut profile_symbols.string_table,
                    //                     &symbol_map,
                    //                 )
                    //             })
                    //             .collect()
                    //     })
                    //     .unwrap_or_default();
                    let frames = Vec::new();

                    lib_symbol_info.address_infos.push(AddressInfo {
                        symbol_name: profile_symbols
                            .string_table
                            .index_for_string(&symbol_map.resolve_symbol_name(si.symbol.name)),
                        symbol_start_address: si.symbol.address,
                        symbol_size: si.symbol.size,
                        frames,
                    });
                } else {
                    // eprintln!("{} + {:x} -> ??", info.name, addr);
                }
            }

            profile_symbols.lib_symbols.push(lib_symbol_info);
        }

        self.profile = self.profile.make_symbolicated_profile(&profile_symbols);
        self.profile.set_symbolicated(true);

        Ok(self)
    }
}

fn convert_address_frame(
    frame: &FrameDebugInfo,
    strtab: &mut SymbolStringTable,
    symbol_map: &SymbolMap,
) -> Option<AddressFrame> {
    let function_handle = symbol_map.resolve_function_name(frame.function?);
    let function_name = strtab.index_for_string(&function_handle);
    let file = frame.file_path.map(|handle| {
        strtab.index_for_string(symbol_map.resolve_source_file_path(handle).raw_path())
    });

    Some(AddressFrame {
        function_name,
        file,
        line: frame.line_number,
        col: frame.column_number,
        function_start_line: frame.function_start_line,
        function_start_col: frame.function_start_column,
    })
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

    let mut rtdata = RuntimeData::new(
        profile,
        process,
        pid,
        1000.0 / frequency as f64,
        PathBuf::from(gd_exe)
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );

    rtdata.initialize();

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
                FrameAddress::ReturnAddress(rdata.process, frame.address)
            },
            category,
            FrameFlags::empty(),
        );

        // For debugging, raw addresses
        // let strh = rdata
        //     .profile
        //     .handle_for_string(&format!("0x{:x} ({})", frame.address, frame.source));
        // let frame_handle =
        //     rdata
        //         .profile
        //         .handle_for_frame_with_label(strh, category, FrameFlags::empty());

        cur_node = Some(rdata.profile.handle_for_stack(frame_handle, cur_node));
    }

    let cpu_delta = CpuDelta::from_millis(rdata.ms_per_sample);

    rdata
        .profile
        .add_sample(s.thread, s.timestamp, cur_node, cpu_delta, 1);
}
