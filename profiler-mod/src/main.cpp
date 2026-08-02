#include <Geode/Geode.hpp>
#include <arc/prelude.hpp>
#include <matjson/reflect.hpp>
#include <dbuf/ByteWriter.hpp>

using namespace geode::prelude;
using namespace arc;

static volatile uint64_t g_objectCreations = 0;
static volatile uint64_t g_objectDeletions = 0;

struct WorkerData {
    std::unordered_map<std::string, int64_t> counters;
};

static WorkerData gatherData() {
    std::unordered_map<std::string, int64_t> counters;
    uint64_t creations = InterlockedOr((volatile LONG*)&g_objectCreations, 0);
    uint64_t deletions = InterlockedOr((volatile LONG*)&g_objectDeletions, 0);
    // log::debug("Creations: {}, Deletions: {}", creations, deletions);

    counters["Objects"] = creations - deletions;
    return {
        std::move(counters)
    };
}

void enableHooks();
void disableHooks();

Future<NetResult<>> socketWorker(uint16_t port) {
    log::info("pre-connect");
    auto stream = ARC_CO_UNWRAP(co_await arc::TcpStream::connect(qsox::SocketAddress{qsox::Ipv4Address::LOCALHOST, port}));
    log::info("Connected to profiler parent on port {}", port);

    auto intvl = arc::interval(asp::Duration::fromMillis(5));
    while (true) {
        co_await intvl.tick();

        // TODO send message
        auto data = matjson::Value{gatherData()}.dump(matjson::NO_INDENTATION);

        dbuf::ByteWriter wr;
        wr.writeStringU32(data);

        auto toSend = wr.written();
        ARC_CO_UNWRAP(co_await stream.send(toSend.data(), toSend.size()));
    }

    co_return Ok();
}

$on_mod(Loaded) {
    auto port = utils::numFromString<uint16_t>(getEnvironmentVariable("GD_PROFILER_PORT")).unwrapOrDefault();
    if (port == 0) return;

    enableHooks();

    arc::spawn([port] -> Future<> {
        auto r = co_await socketWorker(port);
        if (!r) {
            log::error("socket worker failed: {}", r.unwrapErr());
            queueInMainThread(disableHooks);
        }
    });
}

[[gnu::naked]] void ccobject_ctor_detour() {
    __asm {
        // complete the 2 instructions that we overwrote
        mov dword ptr [rcx + 0x8], eax
        mov rax, rcx
        // increment our atomic variable
        lock inc qword ptr [g_objectCreations]
        // return back to caller of CCObject()
        ret
    }
}

[[gnu::naked]] void ccobject_dtor_detour() {
    __asm {
        // increment our atomic variable
        lock inc qword ptr [g_objectDeletions]
        // return back to caller of ~CCObject()
        ret
    }
}

static auto ccobject_ctor_func = (void*)(geode::base::getCocos() + 0xe902);
static auto ccobject_dtor_func = (void*)(geode::base::getCocos() + 0xe992);
static Patch* ccobject_ctor_patch = nullptr;
static Patch* ccobject_dtor_patch = nullptr;

void enableHooks() {
    // CCObject() + 0x42, we have 14 bytes of space here to make the jump
    // we overwrite 2 legit instructions and a return, those being:
    // * mov dword ptr [rcx + 0x8], eax
    // * mov rax, rcx
    std::vector<uint8_t> ccobject_jmp {
        // movabs rdx, 0
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // jmp rdx
        0xff, 0xe2
    };
    auto fnPtr = (void*)&ccobject_ctor_detour;
    std::memcpy(ccobject_jmp.data() + 2, &fnPtr, sizeof(void*));
    ccobject_ctor_patch = Mod::get()->patch(ccobject_ctor_func, ccobject_jmp).unwrapOrDefault();


    // ~CCObject() has enough 0xcc bytes we do not need to overwrite anything besides the ret!
    // ~CCObject() + 0x82
    std::vector<uint8_t> ccobject_dtor_jmp {
        // movabs rdx, 0
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // jmp rdx
        0xff, 0xe2
    };
    fnPtr = (void*)&ccobject_dtor_detour;
    std::memcpy(ccobject_dtor_jmp.data() + 2, &fnPtr, sizeof(void*));
    ccobject_dtor_patch = Mod::get()->patch(ccobject_dtor_func, ccobject_dtor_jmp).unwrapOrDefault();
}

void disableHooks() {
    if (ccobject_ctor_patch) {
        (void) ccobject_dtor_patch->disable();
    }
    if (ccobject_dtor_patch) {
        (void) ccobject_dtor_patch->disable();
    }
}
