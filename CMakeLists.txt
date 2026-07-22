cmake_minimum_required(VERSION 3.15)
project(Inspecthor VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(INSPECTHOR_BUILD_RESOLVER_TEST "Build the focused target resolver test" OFF)
option(INSPECTHOR_BUILD_PROCESS_ACTIVITY_TEST "Build the Process Activity all-findings test" OFF)
option(INSPECTHOR_BUILD_LEGACY_TESTS "Build legacy test-case executables when their sources are present" OFF)

# Prevent Winsock conflicts globally
add_compile_definitions(WIN32_LEAN_AND_MEAN)

# Configure output directories for easy execution
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/x86)
else()
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/x64)
endif()

# Setup thirdparty dependencies
# MinHook static library
add_subdirectory(ThirdParty/minhook EXCLUDE_FROM_ALL)

# Dear ImGui library target
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/ThirdParty/imgui)
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)
target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# Common headers directory
include_directories(src/shared)

# Agent DLL Target
add_library(InspecthorAgent SHARED
    src/agent/agent.cpp
    src/agent/hooks.cpp
    src/agent/filter.cpp
)
target_include_directories(InspecthorAgent PRIVATE src/agent ThirdParty/minhook/include)
target_link_libraries(InspecthorAgent PRIVATE minhook ws2_32 ole32 advapi32)

# Loader EXE Target
add_executable(InspecthorLoader src/loader/loader.cpp)

# Controller EXE Target
add_executable(InspecthorController
    src/controller/controller.cpp
    src/controller/injector.cpp
    src/controller/etw_monitor.cpp
    src/controller/process_tree_manager.cpp
    src/controller/child_instrumentation_policy.cpp
    src/controller/specialized_activity_store.cpp
    src/controller/ai_client.cpp
    src/controller/gui.cpp
    src/controller/inspecthor_resources.rc
)
set_target_properties(InspecthorController PROPERTIES WIN32_EXECUTABLE TRUE)
if(MSVC)
    target_link_options(InspecthorController PRIVATE
        "/ENTRY:mainCRTStartup"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
endif()
target_include_directories(InspecthorController PRIVATE 
    src/controller 
    ThirdParty
)
target_link_libraries(InspecthorController PRIVATE 
    imgui
    d3d11
    dxgi
    d3dcompiler
    comdlg32
    advapi32
    tdh
    dbghelp
    winhttp
    crypt32
    wbemuuid
    iphlpapi
    ws2_32
)

if(INSPECTHOR_BUILD_RESOLVER_TEST)
add_executable(TargetResolverTest tests/TargetResolverTest.cpp src/controller/target_resolver.cpp src/controller/office_target_resolver.cpp)
target_include_directories(TargetResolverTest PRIVATE src/controller)
target_link_libraries(TargetResolverTest PRIVATE advapi32)
endif()

if(INSPECTHOR_BUILD_PROCESS_ACTIVITY_TEST)
add_executable(ProcessAllFindingsTest "Test-case/ProcessAllFindingsTest.cpp")
endif()

if(INSPECTHOR_BUILD_LEGACY_TESTS)
# Test Executable
add_executable(ApiTest tests/ApiTest.cpp)
add_executable(TelemetryIntegrationTest
    tests/TelemetryIntegrationTest.cpp
    src/controller/injector.cpp
)
target_include_directories(TelemetryIntegrationTest PRIVATE src/controller)
add_executable(ProcessSpawnTest tests/ProcessSpawnTest.cpp)
add_executable(CommandExecutionTest tests/CommandExecutionTest.cpp)
add_executable(ThreadCreationTest tests/ThreadCreationTest.cpp)
add_executable(NestedProcessTest tests/NestedProcessTest.cpp)
add_executable(TcpClientTest tests/TcpClientTest.cpp)
add_executable(UdpClientTest tests/UdpClientTest.cpp)
add_executable(HttpWinInetTest tests/HttpWinInetTest.cpp)
add_executable(HttpWinHttpTest tests/HttpWinHttpTest.cpp)
add_executable(DnsQueryTest tests/DnsQueryTest.cpp)
add_executable(NetworkExclusionTest tests/NetworkExclusionTest.cpp)
add_executable(RegistryCreateTest tests/RegistryCreateTest.cpp)
add_executable(RegistryModifyTest tests/RegistryModifyTest.cpp)
add_executable(RegistryDeleteTest tests/RegistryDeleteTest.cpp)
add_executable(RegistryPersistenceTest tests/RegistryPersistenceTest.cpp)
add_executable(RegistryExclusionTest tests/RegistryExclusionTest.cpp)
add_executable(FileCreateTest tests/FileCreateTest.cpp)
add_executable(FileModifyTest tests/FileModifyTest.cpp)
add_executable(FileDeleteTest tests/FileDeleteTest.cpp)
add_executable(FileMoveTest tests/FileMoveTest.cpp)
add_executable(FileCopyTest tests/FileCopyTest.cpp)
add_executable(DirectoryTest tests/DirectoryTest.cpp)
add_executable(FileReconstructionTest tests/FileReconstructionTest.cpp)
add_executable(MemoryActivityTest tests/MemoryActivityTest.cpp)
add_executable(LoadLibraryTest tests/LoadLibraryTest.cpp)
add_executable(GetProcAddressTest tests/GetProcAddressTest.cpp)
add_executable(DynamicApiResolutionTest tests/DynamicApiResolutionTest.cpp)
add_executable(DllSideloadTest tests/DllSideloadTest.cpp)
add_executable(ReflectiveLoadTest tests/ReflectiveLoadTest.cpp)
add_executable(MutexTest tests/MutexTest.cpp)
add_executable(EventTest tests/EventTest.cpp)
add_executable(SemaphoreTest tests/SemaphoreTest.cpp)
add_executable(NamedPipeTest tests/NamedPipeTest.cpp)
add_executable(SharedMemoryTest tests/SharedMemoryTest.cpp)
add_executable(ComObjectTest tests/ComObjectTest.cpp)
add_executable(TaskSchedulerTest tests/TaskSchedulerTest.cpp)
add_executable(WmiQueryTest tests/WmiQueryTest.cpp)
add_executable(WmiPersistenceTest tests/WmiPersistenceTest.cpp)
add_executable(BitsJobTest tests/BitsJobTest.cpp)
add_executable(ShellComTest tests/ShellComTest.cpp)
add_executable(CreateServiceTest tests/CreateServiceTest.cpp)
add_executable(ModifyServiceTest tests/ModifyServiceTest.cpp)
add_executable(StartServiceTest tests/StartServiceTest.cpp)
add_executable(DriverLoadTest tests/DriverLoadTest.cpp)
add_executable(DriverUnloadTest tests/DriverUnloadTest.cpp)
add_executable(IoctlCommunicationTest tests/IoctlCommunicationTest.cpp)
add_executable(RemoteThreadInjectionTest tests/RemoteThreadInjectionTest.cpp)
add_executable(APCInjectionTest tests/APCInjectionTest.cpp)
add_executable(ThreadHijackTest tests/ThreadHijackTest.cpp)
add_executable(SectionMapInjectionTest tests/SectionMapInjectionTest.cpp)
add_executable(ProcessHollowingTest tests/ProcessHollowingTest.cpp)
add_executable(DebuggerCheckTest tests/DebuggerCheckTest.cpp)
add_executable(VmCheckTest tests/VmCheckTest.cpp)
add_executable(SandboxCheckTest tests/SandboxCheckTest.cpp)
add_executable(ProcessEnumTest tests/ProcessEnumTest.cpp)
add_executable(FingerprintTest tests/FingerprintTest.cpp)
add_executable(AESTest tests/AESTest.cpp)
add_executable(RSATest tests/RSATest.cpp)
add_executable(HashTest tests/HashTest.cpp)
add_executable(RandomTest tests/RandomTest.cpp)
add_executable(ConfigDecryptTest tests/ConfigDecryptTest.cpp)
add_executable(RansomwareSimulationTest tests/RansomwareSimulationTest.cpp)
target_link_libraries(CommandExecutionTest PRIVATE shell32)
target_link_libraries(TcpClientTest PRIVATE ws2_32)
target_link_libraries(UdpClientTest PRIVATE ws2_32)
target_link_libraries(HttpWinInetTest PRIVATE wininet)
target_link_libraries(HttpWinHttpTest PRIVATE winhttp)
target_link_libraries(DnsQueryTest PRIVATE dnsapi ws2_32)
target_link_libraries(NetworkExclusionTest PRIVATE ws2_32)
target_link_libraries(ComObjectTest PRIVATE ole32)
target_link_libraries(TaskSchedulerTest PRIVATE ole32)
target_link_libraries(WmiQueryTest PRIVATE ole32)
target_link_libraries(WmiPersistenceTest PRIVATE ole32)
target_link_libraries(BitsJobTest PRIVATE ole32)
target_link_libraries(ShellComTest PRIVATE ole32)
target_link_libraries(CreateServiceTest PRIVATE advapi32)
target_link_libraries(ModifyServiceTest PRIVATE advapi32)
target_link_libraries(StartServiceTest PRIVATE advapi32)
target_link_libraries(DriverLoadTest PRIVATE advapi32)
target_link_libraries(VmCheckTest PRIVATE advapi32)
target_link_libraries(SandboxCheckTest PRIVATE advapi32 user32)
target_link_libraries(FingerprintTest PRIVATE winmm)
target_link_libraries(AESTest PRIVATE advapi32)
target_link_libraries(RSATest PRIVATE advapi32)
target_link_libraries(HashTest PRIVATE advapi32 bcrypt)
target_link_libraries(RandomTest PRIVATE advapi32 bcrypt)
target_link_libraries(ConfigDecryptTest PRIVATE bcrypt)
target_link_libraries(RansomwareSimulationTest PRIVATE advapi32)

set(INSPECTHOR_TEST_TARGETS
    ApiTest
    ProcessSpawnTest
    CommandExecutionTest
    ThreadCreationTest
    NestedProcessTest
    TcpClientTest
    UdpClientTest
    HttpWinInetTest
    HttpWinHttpTest
    DnsQueryTest
    NetworkExclusionTest
    RegistryCreateTest
    RegistryModifyTest
    RegistryDeleteTest
    RegistryPersistenceTest
    RegistryExclusionTest
    FileCreateTest
    FileModifyTest
    FileDeleteTest
    FileMoveTest
    FileCopyTest
    DirectoryTest
    FileReconstructionTest
    MemoryActivityTest
    LoadLibraryTest
    GetProcAddressTest
    DynamicApiResolutionTest
    DllSideloadTest
    ReflectiveLoadTest
    MutexTest
    EventTest
    SemaphoreTest
    NamedPipeTest
    SharedMemoryTest
    ComObjectTest
    TaskSchedulerTest
    WmiQueryTest
    WmiPersistenceTest
    BitsJobTest
    ShellComTest
    CreateServiceTest
    ModifyServiceTest
    StartServiceTest
    DriverLoadTest
    DriverUnloadTest
    IoctlCommunicationTest
    RemoteThreadInjectionTest
    APCInjectionTest
    ThreadHijackTest
    SectionMapInjectionTest
    ProcessHollowingTest
    DebuggerCheckTest
    VmCheckTest
    SandboxCheckTest
    ProcessEnumTest
    FingerprintTest
    AESTest
    RSATest
    HashTest
    RandomTest
    ConfigDecryptTest
    RansomwareSimulationTest
)

if(MSVC)
    foreach(test_target IN LISTS INSPECTHOR_TEST_TARGETS)
        target_compile_options(${test_target} PRIVATE /Zi /Od /Ob0)
        target_link_options(${test_target} PRIVATE /DEBUG)
    endforeach()
endif()
endif()

# Apply architecture-specific names (e.g. InspecthorAgent32.dll for x86)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(InspecthorAgent PROPERTIES OUTPUT_NAME "InspecthorAgent32")
    set_target_properties(InspecthorLoader PROPERTIES OUTPUT_NAME "InspecthorLoader32")
    set_target_properties(InspecthorController PROPERTIES OUTPUT_NAME "InspecthorController32")
    if(INSPECTHOR_BUILD_LEGACY_TESTS)
    set_target_properties(ApiTest PROPERTIES OUTPUT_NAME "ApiTest32")
    set_target_properties(ProcessSpawnTest PROPERTIES OUTPUT_NAME "ProcessSpawnTest32")
    set_target_properties(CommandExecutionTest PROPERTIES OUTPUT_NAME "CommandExecutionTest32")
    set_target_properties(ThreadCreationTest PROPERTIES OUTPUT_NAME "ThreadCreationTest32")
    set_target_properties(NestedProcessTest PROPERTIES OUTPUT_NAME "NestedProcessTest32")
    set_target_properties(TcpClientTest PROPERTIES OUTPUT_NAME "TcpClientTest32")
    set_target_properties(UdpClientTest PROPERTIES OUTPUT_NAME "UdpClientTest32")
    set_target_properties(HttpWinInetTest PROPERTIES OUTPUT_NAME "HttpWinInetTest32")
    set_target_properties(HttpWinHttpTest PROPERTIES OUTPUT_NAME "HttpWinHttpTest32")
    set_target_properties(DnsQueryTest PROPERTIES OUTPUT_NAME "DnsQueryTest32")
    set_target_properties(NetworkExclusionTest PROPERTIES OUTPUT_NAME "NetworkExclusionTest32")
    set_target_properties(RegistryCreateTest PROPERTIES OUTPUT_NAME "RegistryCreateTest32")
    set_target_properties(RegistryModifyTest PROPERTIES OUTPUT_NAME "RegistryModifyTest32")
    set_target_properties(RegistryDeleteTest PROPERTIES OUTPUT_NAME "RegistryDeleteTest32")
    set_target_properties(RegistryPersistenceTest PROPERTIES OUTPUT_NAME "RegistryPersistenceTest32")
    set_target_properties(RegistryExclusionTest PROPERTIES OUTPUT_NAME "RegistryExclusionTest32")
    set_target_properties(FileCreateTest PROPERTIES OUTPUT_NAME "FileCreateTest32")
    set_target_properties(FileModifyTest PROPERTIES OUTPUT_NAME "FileModifyTest32")
    set_target_properties(FileDeleteTest PROPERTIES OUTPUT_NAME "FileDeleteTest32")
    set_target_properties(FileMoveTest PROPERTIES OUTPUT_NAME "FileMoveTest32")
    set_target_properties(FileCopyTest PROPERTIES OUTPUT_NAME "FileCopyTest32")
    set_target_properties(DirectoryTest PROPERTIES OUTPUT_NAME "DirectoryTest32")
    set_target_properties(FileReconstructionTest PROPERTIES OUTPUT_NAME "FileReconstructionTest32")
    set_target_properties(MemoryActivityTest PROPERTIES OUTPUT_NAME "MemoryActivityTest32")
    set_target_properties(LoadLibraryTest PROPERTIES OUTPUT_NAME "LoadLibraryTest32")
    set_target_properties(GetProcAddressTest PROPERTIES OUTPUT_NAME "GetProcAddressTest32")
    set_target_properties(DynamicApiResolutionTest PROPERTIES OUTPUT_NAME "DynamicApiResolutionTest32")
    set_target_properties(DllSideloadTest PROPERTIES OUTPUT_NAME "DllSideloadTest32")
    set_target_properties(ReflectiveLoadTest PROPERTIES OUTPUT_NAME "ReflectiveLoadTest32")
    set_target_properties(MutexTest PROPERTIES OUTPUT_NAME "MutexTest32")
    set_target_properties(EventTest PROPERTIES OUTPUT_NAME "EventTest32")
    set_target_properties(SemaphoreTest PROPERTIES OUTPUT_NAME "SemaphoreTest32")
    set_target_properties(NamedPipeTest PROPERTIES OUTPUT_NAME "NamedPipeTest32")
    set_target_properties(SharedMemoryTest PROPERTIES OUTPUT_NAME "SharedMemoryTest32")
    set_target_properties(ComObjectTest PROPERTIES OUTPUT_NAME "ComObjectTest32")
    set_target_properties(TaskSchedulerTest PROPERTIES OUTPUT_NAME "TaskSchedulerTest32")
    set_target_properties(WmiQueryTest PROPERTIES OUTPUT_NAME "WmiQueryTest32")
    set_target_properties(WmiPersistenceTest PROPERTIES OUTPUT_NAME "WmiPersistenceTest32")
    set_target_properties(BitsJobTest PROPERTIES OUTPUT_NAME "BitsJobTest32")
    set_target_properties(ShellComTest PROPERTIES OUTPUT_NAME "ShellComTest32")
    set_target_properties(CreateServiceTest PROPERTIES OUTPUT_NAME "CreateServiceTest32")
    set_target_properties(ModifyServiceTest PROPERTIES OUTPUT_NAME "ModifyServiceTest32")
    set_target_properties(StartServiceTest PROPERTIES OUTPUT_NAME "StartServiceTest32")
    set_target_properties(DriverLoadTest PROPERTIES OUTPUT_NAME "DriverLoadTest32")
    set_target_properties(DriverUnloadTest PROPERTIES OUTPUT_NAME "DriverUnloadTest32")
    set_target_properties(IoctlCommunicationTest PROPERTIES OUTPUT_NAME "IoctlCommunicationTest32")
    set_target_properties(RemoteThreadInjectionTest PROPERTIES OUTPUT_NAME "RemoteThreadInjectionTest32")
    set_target_properties(APCInjectionTest PROPERTIES OUTPUT_NAME "APCInjectionTest32")
    set_target_properties(ThreadHijackTest PROPERTIES OUTPUT_NAME "ThreadHijackTest32")
    set_target_properties(SectionMapInjectionTest PROPERTIES OUTPUT_NAME "SectionMapInjectionTest32")
    set_target_properties(ProcessHollowingTest PROPERTIES OUTPUT_NAME "ProcessHollowingTest32")
    set_target_properties(DebuggerCheckTest PROPERTIES OUTPUT_NAME "DebuggerCheckTest32")
    set_target_properties(VmCheckTest PROPERTIES OUTPUT_NAME "VmCheckTest32")
    set_target_properties(SandboxCheckTest PROPERTIES OUTPUT_NAME "SandboxCheckTest32")
    set_target_properties(ProcessEnumTest PROPERTIES OUTPUT_NAME "ProcessEnumTest32")
    set_target_properties(FingerprintTest PROPERTIES OUTPUT_NAME "FingerprintTest32")
    set_target_properties(AESTest PROPERTIES OUTPUT_NAME "AESTest32")
    set_target_properties(RSATest PROPERTIES OUTPUT_NAME "RSATest32")
    set_target_properties(HashTest PROPERTIES OUTPUT_NAME "HashTest32")
    set_target_properties(RandomTest PROPERTIES OUTPUT_NAME "RandomTest32")
    set_target_properties(ConfigDecryptTest PROPERTIES OUTPUT_NAME "ConfigDecryptTest32")
    set_target_properties(RansomwareSimulationTest PROPERTIES OUTPUT_NAME "RansomwareSimulationTest32")
    endif()
else()
    set_target_properties(InspecthorAgent PROPERTIES OUTPUT_NAME "InspecthorAgent")
    set_target_properties(InspecthorLoader PROPERTIES OUTPUT_NAME "InspecthorLoader")
    set_target_properties(InspecthorController PROPERTIES OUTPUT_NAME "InspecthorController")
    if(INSPECTHOR_BUILD_LEGACY_TESTS)
    set_target_properties(ApiTest PROPERTIES OUTPUT_NAME "ApiTest")
    set_target_properties(ProcessSpawnTest PROPERTIES OUTPUT_NAME "ProcessSpawnTest")
    set_target_properties(CommandExecutionTest PROPERTIES OUTPUT_NAME "CommandExecutionTest")
    set_target_properties(ThreadCreationTest PROPERTIES OUTPUT_NAME "ThreadCreationTest")
    set_target_properties(NestedProcessTest PROPERTIES OUTPUT_NAME "NestedProcessTest")
    set_target_properties(TcpClientTest PROPERTIES OUTPUT_NAME "TcpClientTest")
    set_target_properties(UdpClientTest PROPERTIES OUTPUT_NAME "UdpClientTest")
    set_target_properties(HttpWinInetTest PROPERTIES OUTPUT_NAME "HttpWinInetTest")
    set_target_properties(HttpWinHttpTest PROPERTIES OUTPUT_NAME "HttpWinHttpTest")
    set_target_properties(DnsQueryTest PROPERTIES OUTPUT_NAME "DnsQueryTest")
    set_target_properties(NetworkExclusionTest PROPERTIES OUTPUT_NAME "NetworkExclusionTest")
    set_target_properties(RegistryCreateTest PROPERTIES OUTPUT_NAME "RegistryCreateTest")
    set_target_properties(RegistryModifyTest PROPERTIES OUTPUT_NAME "RegistryModifyTest")
    set_target_properties(RegistryDeleteTest PROPERTIES OUTPUT_NAME "RegistryDeleteTest")
    set_target_properties(RegistryPersistenceTest PROPERTIES OUTPUT_NAME "RegistryPersistenceTest")
    set_target_properties(RegistryExclusionTest PROPERTIES OUTPUT_NAME "RegistryExclusionTest")
    set_target_properties(FileCreateTest PROPERTIES OUTPUT_NAME "FileCreateTest")
    set_target_properties(FileModifyTest PROPERTIES OUTPUT_NAME "FileModifyTest")
    set_target_properties(FileDeleteTest PROPERTIES OUTPUT_NAME "FileDeleteTest")
    set_target_properties(FileMoveTest PROPERTIES OUTPUT_NAME "FileMoveTest")
    set_target_properties(FileCopyTest PROPERTIES OUTPUT_NAME "FileCopyTest")
    set_target_properties(DirectoryTest PROPERTIES OUTPUT_NAME "DirectoryTest")
    set_target_properties(FileReconstructionTest PROPERTIES OUTPUT_NAME "FileReconstructionTest")
    set_target_properties(MemoryActivityTest PROPERTIES OUTPUT_NAME "MemoryActivityTest")
    set_target_properties(LoadLibraryTest PROPERTIES OUTPUT_NAME "LoadLibraryTest")
    set_target_properties(GetProcAddressTest PROPERTIES OUTPUT_NAME "GetProcAddressTest")
    set_target_properties(DynamicApiResolutionTest PROPERTIES OUTPUT_NAME "DynamicApiResolutionTest")
    set_target_properties(DllSideloadTest PROPERTIES OUTPUT_NAME "DllSideloadTest")
    set_target_properties(ReflectiveLoadTest PROPERTIES OUTPUT_NAME "ReflectiveLoadTest")
    set_target_properties(MutexTest PROPERTIES OUTPUT_NAME "MutexTest")
    set_target_properties(EventTest PROPERTIES OUTPUT_NAME "EventTest")
    set_target_properties(SemaphoreTest PROPERTIES OUTPUT_NAME "SemaphoreTest")
    set_target_properties(NamedPipeTest PROPERTIES OUTPUT_NAME "NamedPipeTest")
    set_target_properties(SharedMemoryTest PROPERTIES OUTPUT_NAME "SharedMemoryTest")
    set_target_properties(ComObjectTest PROPERTIES OUTPUT_NAME "ComObjectTest")
    set_target_properties(TaskSchedulerTest PROPERTIES OUTPUT_NAME "TaskSchedulerTest")
    set_target_properties(WmiQueryTest PROPERTIES OUTPUT_NAME "WmiQueryTest")
    set_target_properties(WmiPersistenceTest PROPERTIES OUTPUT_NAME "WmiPersistenceTest")
    set_target_properties(BitsJobTest PROPERTIES OUTPUT_NAME "BitsJobTest")
    set_target_properties(ShellComTest PROPERTIES OUTPUT_NAME "ShellComTest")
    set_target_properties(CreateServiceTest PROPERTIES OUTPUT_NAME "CreateServiceTest")
    set_target_properties(ModifyServiceTest PROPERTIES OUTPUT_NAME "ModifyServiceTest")
    set_target_properties(StartServiceTest PROPERTIES OUTPUT_NAME "StartServiceTest")
    set_target_properties(DriverLoadTest PROPERTIES OUTPUT_NAME "DriverLoadTest")
    set_target_properties(DriverUnloadTest PROPERTIES OUTPUT_NAME "DriverUnloadTest")
    set_target_properties(IoctlCommunicationTest PROPERTIES OUTPUT_NAME "IoctlCommunicationTest")
    set_target_properties(RemoteThreadInjectionTest PROPERTIES OUTPUT_NAME "RemoteThreadInjectionTest")
    set_target_properties(APCInjectionTest PROPERTIES OUTPUT_NAME "APCInjectionTest")
    set_target_properties(ThreadHijackTest PROPERTIES OUTPUT_NAME "ThreadHijackTest")
    set_target_properties(SectionMapInjectionTest PROPERTIES OUTPUT_NAME "SectionMapInjectionTest")
    set_target_properties(ProcessHollowingTest PROPERTIES OUTPUT_NAME "ProcessHollowingTest")
    set_target_properties(DebuggerCheckTest PROPERTIES OUTPUT_NAME "DebuggerCheckTest")
    set_target_properties(VmCheckTest PROPERTIES OUTPUT_NAME "VmCheckTest")
    set_target_properties(SandboxCheckTest PROPERTIES OUTPUT_NAME "SandboxCheckTest")
    set_target_properties(ProcessEnumTest PROPERTIES OUTPUT_NAME "ProcessEnumTest")
    set_target_properties(FingerprintTest PROPERTIES OUTPUT_NAME "FingerprintTest")
    set_target_properties(AESTest PROPERTIES OUTPUT_NAME "AESTest")
    set_target_properties(RSATest PROPERTIES OUTPUT_NAME "RSATest")
    set_target_properties(HashTest PROPERTIES OUTPUT_NAME "HashTest")
    set_target_properties(RandomTest PROPERTIES OUTPUT_NAME "RandomTest")
    set_target_properties(ConfigDecryptTest PROPERTIES OUTPUT_NAME "ConfigDecryptTest")
    set_target_properties(RansomwareSimulationTest PROPERTIES OUTPUT_NAME "RansomwareSimulationTest")
    endif()
endif()
