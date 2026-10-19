#include <linux/types.h>
#include <linux/cache.h>
#include "feature/attest_spoof.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep

// The actual attestation spoofing runs in ksud + the libinterceptor.so that
// gets injected into keystore2. The kernel only stores the on/off state so
// that `ksuctl GET/SET_FEATURE` works and the manager UI can toggle it
// through the existing feature plumbing.
static bool ksu_attest_spoof_enabled __read_mostly = false;

static int attest_spoof_feature_get(u64 *value)
{
    *value = ksu_attest_spoof_enabled ? 1 : 0;
    return 0;
}

static int attest_spoof_feature_set(u64 value)
{
    bool enable = value != 0;

    ksu_attest_spoof_enabled = enable;
    pr_info("attest_spoof: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler attest_spoof_handler = {
    .feature_id = KSU_FEATURE_ATTEST_SPOOF,
    .name = "attest_spoof",
    .get_handler = attest_spoof_feature_get,
    .set_handler = attest_spoof_feature_set,
};

void __init ksu_attest_spoof_init(void)
{
    if (ksu_register_feature_handler(&attest_spoof_handler)) {
        pr_err("Failed to register attest_spoof feature handler\n");
    }
}

void __exit ksu_attest_spoof_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_ATTEST_SPOOF);
}
