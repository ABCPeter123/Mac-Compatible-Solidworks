/* Independent macOS Vulkan device / robustness2 test.
 * Uses the Khronos Vulkan Headers at a pinned version and dynamically loads
 * a Vulkan loader passed on the command line. It never links proprietary CAD.
 */
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failure(const char *stage, int result) {
    printf("SWCOMPAT_NATIVE_VK_STAGE=%s\n", stage);
    printf("SWCOMPAT_NATIVE_VK_RESULT=%d\n", result);
    printf("SWCOMPAT_NATIVE_VK=FAIL\n");
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return failure("MissingVulkanLoaderPath", -1);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return failure("dlopen", -1);
    }

    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(library, "vkGetInstanceProcAddr");
    if (!gipa) return failure("vkGetInstanceProcAddr", -1);

    PFN_vkEnumerateInstanceExtensionProperties enumerate_extensions =
        (PFN_vkEnumerateInstanceExtensionProperties)gipa(NULL, "vkEnumerateInstanceExtensionProperties");
    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)gipa(NULL, "vkCreateInstance");
    if (!enumerate_extensions || !create_instance) return failure("InstanceEntrypoints", -1);

    uint32_t num_extensions = 0;
    VkResult result = enumerate_extensions(NULL, &num_extensions, NULL);
    if (result != VK_SUCCESS) return failure("CountInstanceExtensions", result);
    VkExtensionProperties *extensions = calloc(num_extensions ? num_extensions : 1, sizeof(*extensions));
    if (!extensions) return failure("OutOfMemory", -1);
    result = enumerate_extensions(NULL, &num_extensions, extensions);
    if (result != VK_SUCCESS) return failure("ReadInstanceExtensions", result);

    int portability = 0;
    for (uint32_t i = 0; i < num_extensions; ++i) {
        if (!strcmp(extensions[i].extensionName, VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME))
            portability = 1;
    }
    free(extensions);

    const char *port_name = VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME;
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "SWCompat Vulkan Features",
        .apiVersion = VK_API_VERSION_1_1,
    };
    VkInstanceCreateInfo info = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .flags = portability ? VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR : 0,
        .pApplicationInfo = &app,
        .enabledExtensionCount = portability ? 1u : 0u,
        .ppEnabledExtensionNames = portability ? &port_name : NULL,
    };
    VkInstance instance = VK_NULL_HANDLE;
    result = create_instance(&info, NULL, &instance);
    printf("SWCOMPAT_NATIVE_VK_INSTANCE_RESULT=%d\n", result);
    if (result != VK_SUCCESS) return failure("vkCreateInstance", result);

    PFN_vkEnumeratePhysicalDevices enum_devices =
        (PFN_vkEnumeratePhysicalDevices)gipa(instance, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties get_properties =
        (PFN_vkGetPhysicalDeviceProperties)gipa(instance, "vkGetPhysicalDeviceProperties");
    PFN_vkGetPhysicalDeviceFeatures2 get_features2 =
        (PFN_vkGetPhysicalDeviceFeatures2)gipa(instance, "vkGetPhysicalDeviceFeatures2");
    PFN_vkEnumerateDeviceExtensionProperties enum_device_extensions =
        (PFN_vkEnumerateDeviceExtensionProperties)gipa(instance, "vkEnumerateDeviceExtensionProperties");
    PFN_vkDestroyInstance destroy =
        (PFN_vkDestroyInstance)gipa(instance, "vkDestroyInstance");
    if (!enum_devices || !get_properties || !get_features2 || !enum_device_extensions || !destroy)
        return failure("DeviceEntrypoints", -1);

    uint32_t count = 0;
    result = enum_devices(instance, &count, NULL);
    if (result != VK_SUCCESS) return failure("CountPhysicalDevices", result);
    printf("SWCOMPAT_NATIVE_VK_DEVICE_COUNT=%u\n", count);
    if (count == 0) return failure("NoPhysicalDevices", -1);
    if (count > 32) count = 32;
    VkPhysicalDevice devices[32] = {0};
    result = enum_devices(instance, &count, devices);
    if (result != VK_SUCCESS && result != VK_INCOMPLETE) return failure("ReadPhysicalDevices", result);

    int found_null_descriptor = 0;
    for (uint32_t i = 0; i < count; ++i) {
        VkPhysicalDeviceProperties props = {0};
        get_properties(devices[i], &props);
        printf("SWCOMPAT_NATIVE_VK_DEVICE_%u=%s\n", i, props.deviceName);

        uint32_t ext_count = 0;
        result = enum_device_extensions(devices[i], NULL, &ext_count, NULL);
        if (result != VK_SUCCESS) return failure("CountDeviceExtensions", result);
        VkExtensionProperties *dev_extensions = calloc(ext_count ? ext_count : 1, sizeof(*dev_extensions));
        if (!dev_extensions) return failure("OutOfMemoryDeviceExtensions", -1);
        result = enum_device_extensions(devices[i], NULL, &ext_count, dev_extensions);
        if (result != VK_SUCCESS) return failure("ReadDeviceExtensions", result);

        int robustness_ext = 0;
        for (uint32_t j = 0; j < ext_count; ++j)
            if (!strcmp(dev_extensions[j].extensionName, VK_EXT_ROBUSTNESS_2_EXTENSION_NAME))
                robustness_ext = 1;
        free(dev_extensions);

        VkPhysicalDeviceRobustness2FeaturesEXT robustness = {
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ROBUSTNESS_2_FEATURES_EXT
        };
        VkPhysicalDeviceFeatures2 features = {
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
            .pNext = robustness_ext ? &robustness : NULL,
        };
        get_features2(devices[i], &features);
        printf("SWCOMPAT_NATIVE_VK_ROBUSTNESS2_EXTENSION_%u=%d\n", i, robustness_ext);
        printf("SWCOMPAT_NATIVE_VK_NULL_DESCRIPTOR_%u=%d\n", i, robustness_ext && robustness.nullDescriptor ? 1 : 0);
        if (robustness_ext && robustness.nullDescriptor) found_null_descriptor = 1;
    }
    destroy(instance, NULL);
    printf("SWCOMPAT_NATIVE_VK_NULL_DESCRIPTOR=%d\n", found_null_descriptor);
    printf("SWCOMPAT_NATIVE_VK=PASS\n");
    return 0;
}
