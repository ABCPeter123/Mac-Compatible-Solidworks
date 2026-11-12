/* Windows x64 Vulkan loader/physical-device smoke test.
   Dynamically resolves Vulkan 1.0 functions, so the build needs no Vulkan SDK.
   Only standard Win32 libraries are linked. The code uses no SOLIDWORKS files. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t VkResult;
typedef uint32_t VkFlags;
typedef struct VkInstance_T *VkInstance;
typedef struct VkPhysicalDevice_T *VkPhysicalDevice;
typedef void (*PFN_vkVoidFunction)(void);

typedef struct {
    uint32_t sType;
    const void *pNext;
    const char *pApplicationName;
    uint32_t applicationVersion;
    const char *pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
} VkApplicationInfo;

typedef struct {
    uint32_t sType;
    const void *pNext;
    VkFlags flags;
    const VkApplicationInfo *pApplicationInfo;
    uint32_t enabledLayerCount;
    const char *const *ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char *const *ppEnabledExtensionNames;
} VkInstanceCreateInfo;

typedef struct {
    char extensionName[256];
    uint32_t specVersion;
} VkExtensionProperties;

typedef PFN_vkVoidFunction (WINAPI *PFN_vkGetInstanceProcAddr)(VkInstance, const char *);
typedef VkResult (WINAPI *PFN_vkEnumerateInstanceVersion)(uint32_t *);
typedef VkResult (WINAPI *PFN_vkEnumerateInstanceExtensionProperties)(const char *, uint32_t *, VkExtensionProperties *);
typedef VkResult (WINAPI *PFN_vkCreateInstance)(const VkInstanceCreateInfo *, const void *, VkInstance *);
typedef VkResult (WINAPI *PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t *, VkPhysicalDevice *);
typedef void (WINAPI *PFN_vkDestroyInstance)(VkInstance, const void *);

static int failure(const char *stage, VkResult result) {
    printf("SWCOMPAT_VULKAN_STAGE=%s\n", stage);
    printf("SWCOMPAT_VULKAN_RESULT=%ld\n", (long)result);
    printf("SWCOMPAT_VULKAN=FAIL\n");
    fflush(stdout);
    return 1;
}

int main(void) {
    HMODULE vulkan = LoadLibraryW(L"vulkan-1.dll");
    if (!vulkan) return failure("LoadLibrary_vulkan_1", (VkResult)GetLastError());
    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)(void *)GetProcAddress(vulkan, "vkGetInstanceProcAddr");
    if (!gipa) return failure("vkGetInstanceProcAddr", (VkResult)GetLastError());
    printf("SWCOMPAT_VULKAN_LOADER=PASS\n");

    PFN_vkEnumerateInstanceVersion enumerate_version =
        (PFN_vkEnumerateInstanceVersion)(void *)gipa(NULL, "vkEnumerateInstanceVersion");
    uint32_t api = 1u << 22;
    if (enumerate_version && enumerate_version(&api) != 0) {
        return failure("EnumerateInstanceVersion", -1);
    }
    printf("SWCOMPAT_VULKAN_VERSION=%u.%u.%u\n", api >> 22, (api >> 12) & 1023u, api & 4095u);

    PFN_vkEnumerateInstanceExtensionProperties enumerate_extensions =
        (PFN_vkEnumerateInstanceExtensionProperties)(void *)gipa(NULL, "vkEnumerateInstanceExtensionProperties");
    PFN_vkCreateInstance create =
        (PFN_vkCreateInstance)(void *)gipa(NULL, "vkCreateInstance");
    if (!enumerate_extensions || !create) return failure("MissingVulkanEntrypoints", -1);

    uint32_t extension_count = 0;
    VkResult result = enumerate_extensions(NULL, &extension_count, NULL);
    if (result != 0) return failure("EnumerateInstanceExtensions", result);
    VkExtensionProperties *extensions = calloc(extension_count ? extension_count : 1, sizeof(*extensions));
    if (!extensions) return failure("OutOfMemory", -1);
    result = enumerate_extensions(NULL, &extension_count, extensions);
    if (result != 0) { free(extensions); return failure("ReadInstanceExtensions", result); }

    int portability = 0;
    for (uint32_t i = 0; i < extension_count; i++) {
        if (!strcmp(extensions[i].extensionName, "VK_KHR_portability_enumeration")) {
            portability = 1;
            break;
        }
    }
    free(extensions);
    printf("SWCOMPAT_VULKAN_PORTABILITY=%d\n", portability);

    const char *portability_name = "VK_KHR_portability_enumeration";
    const VkApplicationInfo app = {0, NULL, "SWCompat Vulkan probe", 1, "SWCompat", 1, api};
    const VkInstanceCreateInfo info = {1, NULL, portability ? 1u : 0u, &app,
                                        0, NULL, portability ? 1u : 0u,
                                        portability ? &portability_name : NULL};
    VkInstance instance = NULL;
    result = create(&info, NULL, &instance);
    printf("SWCOMPAT_VULKAN_INSTANCE_RESULT=%ld\n", (long)result);
    if (result != 0 || !instance) return failure("vkCreateInstance", result);

    PFN_vkEnumeratePhysicalDevices enumerate_devices =
        (PFN_vkEnumeratePhysicalDevices)(void *)gipa(instance, "vkEnumeratePhysicalDevices");
    PFN_vkDestroyInstance destroy =
        (PFN_vkDestroyInstance)(void *)gipa(instance, "vkDestroyInstance");
    if (!enumerate_devices || !destroy) return failure("MissingDeviceEntrypoints", -1);

    uint32_t devices = 0;
    result = enumerate_devices(instance, &devices, NULL);
    printf("SWCOMPAT_VULKAN_DEVICE_RESULT=%ld\n", (long)result);
    printf("SWCOMPAT_VULKAN_DEVICE_COUNT=%u\n", devices);
    destroy(instance, NULL);
    if (result != 0) return failure("vkEnumeratePhysicalDevices", result);
    if (devices == 0) return failure("NoPhysicalDevices", -1);
    printf("SWCOMPAT_VULKAN=PASS\n");
    return 0;
}
