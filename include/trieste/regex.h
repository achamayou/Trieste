// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "source.h"

#ifdef TRIESTE_REGEX_IMPL_QJSRE
#include "regex_qjsre.h"
#else
#include "regex_re2.h"
#endif