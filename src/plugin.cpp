// Copyright (c) 2011-2015 Zeex
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <cstdlib>
#include <cstring>
#include <functional>
#include <subhook.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <stdio.h>
#endif
#include "amxxmodule.h"
#include <thread>
#include <chrono>
extern void *pAMXFunctions;
// amx_Exec() hook. This hook is used to intercept calls to public functions.
subhook::Hook exec_hook;

bool Inited = false;
extern void debugThread();
extern void amx_dbgexec(AMX* amx, cell* retval, int index);
int AMXAPI amx_Exec_Profiler(AMX *amx, cell *retval, int index) {
#define AMX_FLAG_BROWSE 0x4000  /* busy browsing */
  if (amx->flags & AMX_FLAG_BROWSE) {
    // Not an actual exec, just some internal AMX hack.
    return MF_AmxExec(amx, retval, index);
  } else {
    amx_dbgexec(amx, retval,  index);
    return MF_AmxExec(amx, retval, index);
  }
}

void OnAmxxAttach()
{
  if (!Inited)
  {
    std::thread(debugThread).detach();
    Inited = true;
  }
  exec_hook.Install(MF_AmxExec,
                    amx_Exec_Profiler);
  MF_AmxExec = (PFN_AMX_EXEC)exec_hook.GetTrampoline();

}

void OnAmxxDetach()
{

}
