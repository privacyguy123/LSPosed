/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2020 EdXposed Contributors
 * Copyright (C) 2021 LSPosed Contributors
 */

//
// Created by kotori on 2/4/21.
//

#ifndef LSPOSED_NATIVE_API_H
#define LSPOSED_NATIVE_API_H

#include <dlfcn.h>
#include <dobby.h>

#include <cstdint>
#include <string>

#include "config.h"
#include "utils/hook_helper.hpp"

typedef int (*HookFunType)(void *func, void *replace, void **backup);

typedef int (*UnhookFunType)(void *func);

typedef void (*NativeOnModuleLoaded)(const char *name, void *handle);

typedef struct {
    uint32_t version;
    HookFunType hookFunc;
    UnhookFunType unhookFunc;
} NativeAPIEntries;

typedef NativeOnModuleLoaded (*NativeInit)(const NativeAPIEntries *entries);

namespace lspd {
bool InstallNativeAPI(const lsplant::HookHandler &handler);

void RegisterNativeLib(const std::string &library_name);

inline int HookInline(void *original, void *replace, void **backup) {
    Dl_info info;
    if constexpr (isDebug) {
        if (dladdr(original, &info))
            LOGD("Dobby hooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
    }
    if (!info.dli_sname) return 1;
    return DobbyHook(original, reinterpret_cast<dobby_dummy_func_t>(replace),
                     reinterpret_cast<dobby_dummy_func_t *>(backup));
}

inline int UnhookInline(void *original) {
    Dl_info info;
    if constexpr (isDebug) {
        if (dladdr(original, &info))
            LOGD("Dobby unhooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
    }
    if (!info.dli_sname) return 1;
    return DobbyDestroy(original);
}
}  // namespace lspd

#endif  // LSPOSED_NATIVE_API_H
