#include "debugger.h"
#include <sstream>
#include <vector>
#include <deque>
#include <assert.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include "amx/amxdbg.h"
#include <brynet/net/SocketLibFunction.hpp>
#include <brynet/net/EventLoop.hpp>
#include <brynet/net/TcpService.hpp>
#include <brynet/net/PromiseReceive.hpp>
#include <brynet/net/http/HttpFormat.hpp>
#include <brynet/net/ListenThread.hpp>
#include <brynet/net/wrapper/ServiceBuilder.hpp>
#include <brynet/net/wrapper/ConnectionBuilder.hpp>
#include "utlbuffer.h"
#include <fstream>

using namespace brynet;
using namespace brynet::net;
using namespace brynet::net::http;

enum DebugState
{
  DebugDead = -1,
  DebugRun = 0,
  DebugBreakpoint,
  DebugPause,
  DebugStepIn,
  DebugStepOver,
  DebugStepOut
};
enum MessageType
{
  Diagnostics = 0,
  RequestFile,
  File,

  StartDebugging,
  StopDebugging,
  Pause,
  Continue,

  RequestCallStack,
  CallStack,

  ClearBreakpoints,
  SetBreakpoint,

  HasStopped,
  HasContinued,

  StepOver,
  StepIn,
  StepOut,

  RequestSetVariable,
  SetVariable,
  RequestVariables,
  Variables,

  RequestEvaluate,
  Evaluate,

  Disconnect,
  TotalMessages
};

std::vector<std::string> split_string(const std::string& str,
  const std::string& delimiter)
{
  std::vector<std::string> strings;

  std::string::size_type pos = 0;
  std::string::size_type prev = 0;
  while ((pos = str.find(delimiter, prev)) != std::string::npos)
  {
    strings.push_back(str.substr(prev, pos - prev));
    prev = pos + 1;
  }

  // To get the last substring (or only, if delimiter is not found)
  strings.push_back(str.substr(prev));

  return strings;
}

void removeClientID(const TcpConnection::Ptr& session);
class DebuggerClient
{
public:
  TcpConnection::Ptr socket;
  unsigned char CurrentState = DebugRun;
  std::vector<std::string> files;
  std::string current_file;
  int DebugState = 0;

  struct variable_s
  {
    std::string name;
    std::string value;
    std::string type;
  };

  struct call_stack_s
  {
    int line;
    std::string name;
    std::string filename;
  };

  struct breakpoint_s
  {
    long line;
    std::string filename;
  };
public:
  bool receive_walk_cmd = false;
  std::mutex mtx;
  std::condition_variable cv;
  AMX* amx;
  long current_line;
  std::map<std::string, std::vector<long>> break_list;
  int current_state = 0;
  cell lastfrm;


  DebuggerClient(const TcpConnection::Ptr& tcp_connection)
    : socket(tcp_connection)
  {

  }

  ~DebuggerClient()
  {
    stopDebugging();
    printf("Im dying!\n");
  }
  
  void setBreakpoint(std::string path, int line, int id)
  {
    auto found = break_list.find(path);
    if(found != break_list.end())
    {
      found->second.push_back(line);
    }
    else
    {
      break_list.insert({path, std::vector<long>({ line }) });
    }
  }

  void clearBreakpoints(std::string fileName)
  {
    auto found = break_list.find(fileName);
    if (found != break_list.end())
    {
      found->second.clear();
    }
  }

  enum {
    DISP_DEFAULT = 0x10,
    DISP_STRING = 0x20,
    DISP_BIN = 0x30,   /* ??? not implemented */
    DISP_HEX = 0x40,
    DISP_BOOL = 0x50,
    DISP_FIXED = 0x60,
    DISP_FLOAT = 0x70
  };
#define MAX_DIMS        3 
#define DISP_MASK 0x0f

  char* get_string(AMX* amx, AMX_DBG_SYMBOL* sym, int maxlength)
  {
  #define MAXLINELENGTH   128
    static char string[MAXLINELENGTH];
    char* ptr;
    cell* addr;
    cell base;
    int length, num;

    assert(sym->ident == iARRAY || sym->ident == iREFARRAY);
    assert(sym->dim == 1);
    assert(maxlength < MAXLINELENGTH);
    string[0] = '\0';

    /* get the starting address and the length of the string */
    base = sym->address;
    if (amx_GetAddr(amx, base, &addr) == AMX_ERR_NONE) {
      amx_StrLen(addr, &length);
      if(length > maxlength)
      {
        length = maxlength;
      }
      /* allocate a temporary buffer */
      ptr = (char*)malloc(length + 1);
      if (ptr != NULL) {
        amx_GetString(ptr, addr, 0, length + 1);
        num = length;
        if (num >= maxlength) {
          num = maxlength - 1;
          if (num > 3)
            num -= 3;         /* make space for the ... terminator */
        } /* if */
        assert(num >= 0);
        strncpy(string, ptr, num);
        string[num] = '\0';
        if (num < length && num == maxlength - 3)
          strcat(string, "...");
        free(ptr);
      } /* if */
    }
    else {
      strcpy(string, "?");
    } /* if */
    return string;
  }

  static int get_symbolvalue(AMX* amx, AMX_DBG_SYMBOL* sym, int index, cell* value)
  {
    cell* vptr;
    cell base = sym->address;
    if (sym->vclass & DISP_MASK)
      base += amx->frm;     /* addresses of local vars are relative to the frame */
    if (sym->ident == iREFERENCE || sym->ident == iREFARRAY) {   /* a reference */
      amx_GetAddr(amx, base, &vptr);
      base = *vptr;
    } /* if */
    if (amx_GetAddr(amx, (cell)(base + index * sizeof(cell)), &vptr) != AMX_ERR_NONE)
      return 0;
    *value = *vptr;
    return 1;
  }
  void printvalue(long value, int disptype, std::string& out_value, std::string& out_type)
  {
    char out[64];
    if (disptype == DISP_FLOAT) {
      out_type = "float";
      sprintf(out, "%f", amx_ctof(value));
    }
    else if (disptype == DISP_FIXED) {
      out_type = "fixed";
#define MULTIPLIER 1000
      long ipart = value / MULTIPLIER;
      value -= MULTIPLIER * ipart;
      if (value < 0)
        value = -value;
      sprintf(out,"%ld.%03ld", ipart, value);
    }
    else if (disptype == DISP_HEX) {
      out_type = "hex";
      sprintf(out,"%lx", value);
    }
    else if (disptype == DISP_BOOL) {
      out_type = "bool";
      switch (value) {
      case 0:
        sprintf(out,"false");
        break;
      case 1:
        sprintf(out,"true");
        break;
      default:
        sprintf(out,"%ld (true)", value);
        break;
      } /* switch */
    }
    else {
      out_type = "cell";
      sprintf(out,"%ld", value);
    } /* if */
    out_value += out;
  }

  variable_s display_variable(AMX* amx, AMX_DBG* amxdbg, AMX_DBG_SYMBOL* sym, int index[3], int idxlevel, bool noarray = false)
  {
    variable_s var;
    var.name = sym->name;
    var.type = "N/A";
    var.value = "";
    const AMX_DBG_SYMDIM* symdim;
    cell value;

    assert(index != NULL);
    /* set default display type for the symbol (if none was set) */
    if ((sym->vclass & ~DISP_MASK) == 0) {
      const char* tagname;
      if (dbg_GetTagName(amxdbg, sym->tag, &tagname) == AMX_ERR_NONE) {
        if (stricmp(tagname, "bool") == 0)
          sym->vclass |= DISP_BOOL;
        else if (stricmp(tagname, "fixed") == 0)
          sym->vclass |= DISP_FIXED;
        else if (stricmp(tagname, "float") == 0)
          sym->vclass |= DISP_FLOAT;
      } /* if */
      if ((sym->vclass & ~DISP_MASK) == 0 && (sym->ident == iARRAY || sym->ident == iREFARRAY) && sym->dim == 1) {
        /* untagged array with a single dimension, walk through all elements
         * and check whether this could be a string
         */
        unsigned char* ptr = (unsigned char*)get_string(amx, sym, MAXLINELENGTH - 1);
        int i;
        for (i = 0; i < MAXLINELENGTH - 1 && ptr[i] != '\0'; i++) {
          if ((ptr[i] < ' ' && ptr[i] != '\n' && ptr[i] != '\r' && ptr[i] != ' ')
            || ptr[i] >= 128)
            break;  /* non-ASCII character */
          if (i == 0 && !isalpha(ptr[i]))
            break;  /* want a letter at the start */
        } /* for */
        if (i > 0 && i < MAXLINELENGTH - 1 && ptr[i] == '\0')
          sym->vclass |= DISP_STRING;
      } /* if */
    } /* if */

    if ((sym->ident == iARRAY || sym->ident == iREFARRAY) && idxlevel == 0) {
      if ((sym->vclass & ~DISP_MASK) == DISP_STRING) {
        sym->vclass |= DISP_STRING;
      }
    }
    if ((sym->ident == iARRAY || sym->ident == iREFARRAY)) {
      int dim;
      dbg_GetArrayDim(amxdbg, sym, &symdim);
      /* check whether any of the indices are out of range */
      for (dim = 0; dim < idxlevel; dim++)
        if (symdim[dim].size > 0 && (ucell)index[dim] >= symdim[dim].size)
          break;
      if (dim < idxlevel) {
        if(!noarray)
          var.type = "Array";        
        return var;
      } /* if */
    } /* if */


    if ((sym->ident == iARRAY || sym->ident == iREFARRAY) && idxlevel == 0) {
      if ((sym->vclass & ~DISP_MASK) == DISP_STRING) {

        var.type = "String";
        var.value = get_string(amx, sym, 40);
      }
      else if (sym->dim == 1) {
        ucell len, i;
        len = symdim[0].size;
        if (len == 0)
          len = 1;  /* unknown array length, assume at least 1 element */

        for (i = 0; i < len; i++) {
          if (i > 0)
            var.value += ",";
          if (get_symbolvalue(amx, sym, (int)i, &value))
            printvalue(value, (sym->vclass & ~DISP_MASK), var.value, var.type);
          else
            var.value += "?";


          if (!noarray)
            var.type = "Array";
        } /* for */
        if (len < symdim[0].size || symdim[0].size == 0)
          var.value += ",...";
      }
      else {
        var.value = "(multi-dimensional array)";
      } /* if */
    }
    else if (sym->ident != iARRAY && sym->ident != iREFARRAY && idxlevel > 0) {
      /* index used on a non-array */
      var.value = "(invalid index, not an array)";
    }
    else {
      /* simple variable, or indexed array element */
      int base = 0;
      int dim;
      assert(idxlevel > 0 || index[0] == 0);  /* index should be zero if non-array */
      for (dim = 0; dim < idxlevel - 1; dim++) {
        base += index[dim];
        if (!get_symbolvalue(amx, sym, base, &value))
          break;
        base += value / sizeof(cell);

        if (!noarray)
          var.type = "Array";
      } /* while */
      if (get_symbolvalue(amx, sym, base + index[dim], &value) && sym->dim == idxlevel)
        printvalue(value, (sym->vclass & ~DISP_MASK), var.value, var.type);
      else if (sym->dim != idxlevel)
        var.value = ("(invalid number of dimensions)");
      else
        var.value = ("?");
    } /* if */

    return var;
  }

  void evaluateVar(int frame_id, char* variable)
  {
    if (current_state != DebugRun)
    {
      Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER]; pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];
      if (pDebugger && pDebugger->m_pAmxDbg)
      {
        auto amxdbg = pDebugger->m_pAmxDbg;
        const AMX_DBG_SYMBOL* sym;
        if (dbg_GetVariable(amxdbg, variable, amx->cip, &sym) == AMX_ERR_NONE)
        {
          int idx[MAX_DIMS], dim;
          dim = 0;
          memset(idx, 0, sizeof idx);
          auto var = display_variable(amx, amxdbg, (AMX_DBG_SYMBOL*)sym, idx, dim);
          CUtlBuffer buffer;
          buffer.PutUnsignedInt(0);
          {
            buffer.PutChar(MessageType::Evaluate);
            buffer.PutInt(var.name.size() + 1);
            buffer.PutString(var.name.c_str());
            buffer.PutInt(var.value.size() + 1);
            buffer.PutString(var.value.c_str());;
            buffer.PutInt(var.type.size() + 1);
            buffer.PutString(var.type.c_str());
            buffer.PutInt(0);
          }
          *(uint32_t*)buffer.Base() = buffer.TellPut() - 5;
          socket->send(static_cast<const char*>(buffer.Base()), static_cast<size_t>(buffer.TellPut()));
        }
      }
    }
  }

  int set_symbolvalue(AMX* amx, const AMX_DBG_SYMBOL* sym, int index, cell value)
  {
    cell* vptr;
    cell base = sym->address;
    if (sym->vclass & DISP_MASK)
      base += amx->frm;     /* addresses of local vars are relative to the frame */
    if (sym->ident == iREFERENCE || sym->ident == iREFARRAY) {   /* a reference */
      amx_GetAddr(amx, base, &vptr);
      base = *vptr;
    } /* if */
    if (amx_GetAddr(amx, (cell)(base + index * sizeof(cell)), &vptr) != AMX_ERR_NONE)
      return 0;
    *vptr = value;
    return 1;
  }

  void setVariable(std::string var, std::string value, int index)
  {
    bool success = false;
    bool valid_value = true;
    if (current_state != DebugRun)
    {
      Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER]; pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];
      if (pDebugger && pDebugger->m_pAmxDbg)
      {
        cell result = 0;
        auto amxdbg = pDebugger->m_pAmxDbg;
        const AMX_DBG_SYMBOL* sym;
        size_t lastChar = 0;
        value.erase(remove(value.begin(), value.end(), '\"'), value.end());
        if (dbg_GetVariable(amxdbg, var.c_str(), amx->cip, (const AMX_DBG_SYMBOL**)&sym) == AMX_ERR_NONE)
        {
            if ((sym->ident == iARRAY || sym->ident == iREFARRAY)) {
                if ((sym->vclass & ~DISP_MASK) == DISP_STRING) {
                    cell* addr;
                    auto base = sym->address;
                    const AMX_DBG_SYMDIM* symdim;
                    dbg_GetArrayDim(amxdbg, sym, &symdim);
                    if (amx_GetAddr(amx, base, &addr) == AMX_ERR_NONE) {
                        int packed = 0;
                        if ((ucell)*addr > UNPACKEDMAX) {
                            /* source string is packed */
                            packed = 1;
                        }
                        success = !amx_SetString(addr, value.c_str(), packed, 0, symdim->size);
                    }
                }
            }
            valid_value = false;
        }
        else
        {
            try {
                int intvalue = std::stoi(value, &lastChar);
                if (lastChar == value.size())
                {
                    result = intvalue;
                }
                else
                {
                    auto val = std::stof(value, &lastChar);
                    result = amx_ftoc(val);
                }
            }
            catch (...) {
                // ??? some text or bool
                if (value == "true")
                {
                    result = 1;
                }
                else if (value == "false")
                {
                    result = 0;
                }
                else
                {
                    valid_value = false;
                }
            }
        }
        
        if (valid_value && (dbg_GetVariable(amxdbg, var.c_str(), amx->cip, (const AMX_DBG_SYMBOL**)&sym) == AMX_ERR_NONE))
        {
          success = set_symbolvalue(amx, sym, (int)index, (cell)result);
        }        
      }
    }
    CUtlBuffer buffer;
    buffer.PutUnsignedInt(0);
    {
      buffer.PutChar(MessageType::SetVariable);
      buffer.PutInt(success);
    }
    *(uint32_t*)buffer.Base() = buffer.TellPut() - 5;
    socket->send(static_cast<const char*>(buffer.Base()), static_cast<size_t>(buffer.TellPut()));
  }

  void sendVariables(char *scope)
  {
    bool local_scope = strstr(scope, ":%local%");
    bool global_scope = strstr(scope, ":%global%");
    if (current_state != DebugRun)
    {
      Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER]; pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];
      
      if (pDebugger && pDebugger->m_pAmxDbg)
      {
        int idx[MAX_DIMS], dim;
        dim = 0;
        memset(idx, 0, sizeof idx);
        auto amxdbg = pDebugger->m_pAmxDbg;
        const AMX_DBG_SYMBOL* sym;
        std::vector<variable_s> vars;
        if (local_scope || global_scope)
        {
          for (int i = 0; i < amxdbg->hdr->symbols; i++) {
            if (amxdbg->symboltbl[i]->ident != iFUNCTN
              && amxdbg->symboltbl[i]->codestart <= (ucell)amx->cip
              && amxdbg->symboltbl[i]->codeend > (ucell)amx->cip)
            {
              auto var = display_variable(amx, amxdbg, amxdbg->symboltbl[i], idx, 0);
              if (local_scope)
              {
                if ((amxdbg->symboltbl[i]->vclass & DISP_MASK) > 0)
                {
                  vars.push_back(var);
                }
              }
              else
              {
                if (!((amxdbg->symboltbl[i]->vclass & DISP_MASK) > 0))
                {
                  vars.push_back(var);
                }
              }
            }
          }
        }
        else
        {
          if (dbg_GetVariable(amxdbg, scope, amx->cip, &sym) == AMX_ERR_NONE)
          {
            int idx[MAX_DIMS], dim;
            dim = 0;
            memset(idx, 0, sizeof idx);
            auto var = display_variable(amx, amxdbg, (AMX_DBG_SYMBOL*)sym, idx, dim, true);
            std::string var_name = scope;
            auto values = split_string(var.value, ",");
            int i = 0;
            for(auto val: values)
            {
              vars.push_back({ std::to_string(i), val, var.type });
              i++;
            }
          }
        }
        CUtlBuffer buffer;
        buffer.PutUnsignedInt(0);
        buffer.PutChar(Variables);
        buffer.PutInt(vars.size());
        for (auto var : vars)
        {
          buffer.PutInt(var.name.size() + 1);
          buffer.PutString(var.name.c_str());
          buffer.PutInt(var.value.size() + 1);
          buffer.PutString(var.value.c_str());;
          buffer.PutInt(var.type.size() + 1);
          buffer.PutString(var.type.c_str());
          buffer.PutInt(0);
        }
        *(uint32_t*)buffer.Base() = buffer.TellPut() - 5;
        socket->send(static_cast<const char*>(buffer.Base()), static_cast<size_t>(buffer.TellPut()));
      }
    }
  }

  void CallStack()
  {
    std::vector<call_stack_s> callStack;
    if(current_state != DebugRun)
    {
      Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER]; pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];
      trace_info_t* pTrace = pDebugger->GetTraceStart();
      int count = 0;
      long lLine;
      const char* file, * function;
      while (pTrace)
      {
        pDebugger->GetTraceInfo(pTrace, lLine, function, file);
        callStack.push_back({ lLine, function, current_file });
        pTrace = pDebugger->GetNextTrace(pTrace);
      }
      if (pDebugger->m_pAmxDbg)
      {
        if (!callStack.empty())
        {
          callStack[0].line = current_line-1;
          callStack[0].filename = current_file;
        }
        else
        {
          callStack.push_back({ current_line-1, std::to_string(current_line - 1), current_file });
        }
      }
    }

    CUtlBuffer buffer;
    buffer.PutUnsignedInt(0);
    {
      buffer.PutChar(MessageType::CallStack);
      buffer.PutInt(callStack.size());
      for(auto stack : callStack)
      {
        buffer.PutInt(stack.name.size() + 1);        
        buffer.PutString(stack.name.c_str());
        buffer.PutInt(stack.filename.size() + 1);
        buffer.PutString(stack.filename.c_str());
        buffer.PutInt(stack.line+1);
      }
    }
    *(uint32_t*)buffer.Base() = buffer.TellPut() - 5;
    socket->send(static_cast<const char*>(buffer.Base()), static_cast<size_t>(buffer.TellPut()));
  }

  void WaitWalkCmd()
  {
    if (!receive_walk_cmd)
    {
      CUtlBuffer buffer;
      {
        buffer.PutUnsignedInt(0);
        {
          buffer.PutChar(MessageType::HasStopped);
          std::string stop_msg = "Stopped";
          buffer.PutInt(stop_msg.size() + 1);
          buffer.PutString(stop_msg.c_str());
          buffer.PutInt(stop_msg.size() + 1);
          buffer.PutString(stop_msg.c_str());
          buffer.PutInt(stop_msg.size() + 1);
          buffer.PutString(stop_msg.c_str());
        }
        *(uint32_t*)buffer.Base() = buffer.TellPut() - 5;
      }
      socket->send(static_cast<const char*>(buffer.Base()), static_cast<size_t>(buffer.TellPut()));
      std::unique_lock<std::mutex> lck(mtx);
      cv.wait(lck, [this] { return receive_walk_cmd; });
    }
  }



  int (AMXAPI DebugHook)(AMX* amx)
  {
    if (current_state == DebugDead)
      return current_state;

    this->amx = amx;
    receive_walk_cmd = false;
    Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];

    if (!pDebugger)
      return current_state;

    AMX_DBG* amxdbg = pDebugger->m_pAmxDbg;

    if (!amxdbg)
      return current_state;
    
    static long lastline = 0;
    dbg_LookupLine(amxdbg, amx->cip, &current_line);
    AMX_DBG_LINE test = { amx->cip };
    /* dont break twice */
    if(current_line == lastline)    
      return current_state;
    
    lastline = current_line;
    if (current_state == DebugStepOut && amx->frm > lastfrm)
      current_state = DebugStepIn;
    
    if(current_state == DebugPause || current_state == DebugStepIn)
    {
      WaitWalkCmd();
    }
    else 
    {
      auto found = break_list.find(current_file);      
      if (found != break_list.end())
      {
        for (auto br : found->second)
        {
          if (current_line == br || (current_line+1 == br))
          {
            current_line = br;
            current_state = DebugBreakpoint;
            WaitWalkCmd();
            break;
          }
        }
      }
      
    }

    /* check whether we are stepping through a sub-function */
    if (current_state == DebugStepOver) {
      if (amx->frm < lastfrm)
        return current_state;
      else
        WaitWalkCmd();
      if (current_state == DebugDead)
        return DebugDead;
    }

    switch (current_state)
    {
    case DebugStepIn:
      break;
    case DebugStepOut:
    case DebugStepOver:
      lastfrm = amx->frm;
      break;
    }

    return current_state;
  } 

  void SwitchState(unsigned char state)
  {
    current_state = state;
    receive_walk_cmd = true;
    cv.notify_one();
  }

  void AskFile()
  {
    
  }

  
  void RecvDebugFile(CUtlBuffer* buf)
  {
    char file[260];
    int strlen = buf->GetInt();
    buf->GetString(file, strlen);
    current_file = std::string(file);
    files.push_back(current_file);
  }

  void RecvStateSwitch(CUtlBuffer* buf)
  {
    CurrentState = buf->GetUnsignedChar();
    SwitchState(CurrentState);
  }

  void RecvCallStack(CUtlBuffer* buf)
  {
    CallStack();
  }
  
  void recvRequestVariables(CUtlBuffer* buf)
  {
    char scope[256];
    int strlen = buf->GetInt();
    buf->GetString(scope, strlen);
    sendVariables(scope);
  }

  void recvRequestEvaluate(CUtlBuffer* buf)
  {
    int frameId; char variable[256];
    int strlen = buf->GetInt();
    buf->GetString(variable, strlen);
    frameId = buf->GetInt();
    evaluateVar(frameId, variable);
  }

  void recvDisconnect(CUtlBuffer* buf)
  {
    
  }


  void recvBreakpoint(CUtlBuffer* buf)
  {    
    char path[256];
    int strlen = buf->GetInt();
    buf->GetString(path, strlen);
    std::string filename(path);
    auto found = std::find_if(files.begin(), files.end(), [filename](std::string file) {  return file == filename; });
    if(found == files.end())
    {
      files.push_back(path);
    }
    int line = buf->GetInt();
    int id = buf->GetInt();
    setBreakpoint(path, line, id);
  }

  void recvClearBreakpoints(CUtlBuffer* buf)
  {
    char path[256];
    int strlen = buf->GetInt();
    buf->GetString(path, strlen);
    clearBreakpoints(path);
  }

  void stopDebugging()
  {
    if (!receive_walk_cmd)
    {
      current_state = DebugDead;
      receive_walk_cmd = true;
      cv.notify_one();
    }    
  }

  void recvStopDebugging(CUtlBuffer* buf)
  {
    stopDebugging();
    removeClientID(socket);
  }
  
  void recvRequestSetVariable(CUtlBuffer* buf)
  {
    char var[256];
    int strlen = buf->GetInt();
    buf->GetString(var, strlen);
    char value[256];
    strlen = buf->GetInt();
    buf->GetString(value, strlen);
    auto index = buf->GetInt();
    setVariable(var, value, index);
  }

  void RecvCmd(const char* buffer, size_t len)
  {
    CUtlBuffer buf(buffer, len);

    while (buf.TellGet() < len)
    {
      int msg_len = buf.GetUnsignedInt();
      int type = buf.GetUnsignedChar();
      switch (type)
      {
      case RequestFile:
      {
        RecvDebugFile(&buf);
        break;
      }
      case Pause:
      {
        RecvStateSwitch(&buf);
        break;
      }
      case Continue:
      {
        RecvStateSwitch(&buf);
        break;
      }
      case StepIn:
      {
        RecvStateSwitch(&buf);
        break;
      }
      case StepOver:
      {
        RecvStateSwitch(&buf);
        break;
      }
      case StepOut:
      {
        RecvStateSwitch(&buf);
        break;
      }
      case RequestCallStack:
      {
        RecvCallStack(&buf);
        break;
      }
      case RequestVariables:
      {
        recvRequestVariables(&buf);
        break;
      }
      case RequestEvaluate:
      {
        recvRequestEvaluate(&buf);
        break;
      }
      case Disconnect:
      {
        recvDisconnect(&buf);
        break;
      }
      case ClearBreakpoints:
      {
       recvClearBreakpoints(&buf);
        break;
      }
      case SetBreakpoint:
      {
        recvBreakpoint(&buf);
        break;        
      }
      case StopDebugging:
      {
        recvStopDebugging(&buf);
        break;
      }
      case RequestSetVariable:
      {
        recvRequestSetVariable(&buf);
        break;
      }
      }
    }
  }
};

std::vector<std::unique_ptr<DebuggerClient>> clients;


void addClientID(const TcpConnection::Ptr& session)
{
  clients.push_back(std::make_unique<DebuggerClient>(session));
  clients.back()->AskFile();
}

void removeClientID(const TcpConnection::Ptr& session)
{
  for (auto it = clients.begin(); it != clients.end(); ++it)
  {
    if ((*it)->socket == session)
    {
      clients.erase(it);
      break;
    }
  }
}

void debugThread()
{
  auto service = TcpService::Create();
  service->startWorkerThread(2);

  auto mainLoop = std::make_shared<EventLoop>();
  auto enterCallback = [mainLoop](const TcpConnection::Ptr& session) {
    mainLoop->runAsyncFunctor([session]() {

      addClientID(session);
      });
        session->setDisConnectCallback([mainLoop](const TcpConnection::Ptr& session) {
        mainLoop->runAsyncFunctor([session]() {
        removeClientID(session);
        });
      });
        auto contentLength = std::make_shared<size_t>();
        session->setDataCallback([session](const char* buffer, size_t len) {
        for (auto &client : clients)
        {
          if(client->socket == session)
          {
              client->RecvCmd(buffer, len);
              break;
          }
        }
        return len;
      });
  };

  wrapper::ListenerBuilder listener;
  listener.configureService(service)
    .configureSocketOptions({
      [](TcpSocket& socket) {
        socket.setNodelay();
      }
      })
    .configureConnectionOptions({
      brynet::net::AddSocketOption::WithMaxRecvBufferSize(1024 * 1024),
      brynet::net::AddSocketOption::AddEnterCallback(enterCallback)
      })
        .configureListen([=](wrapper::BuildListenConfig config) {
        config.setAddr(false, "0.0.0.0", 1234);
          })
        .asyncRun();

          while (true)
          {
            mainLoop->loop(1000);
          }
}

struct debug_s
{
  AMX* orig_amx;
  AMX_DEBUG orig;
};
std::vector<debug_s> debug_hooks;

int (AMXAPI AmxxDebug)(tagAMX* amx)
{
  Debugger* pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER]; 
  if (pDebugger)
  {
    AMX_DBG* amxdbg = pDebugger->m_pAmxDbg;
    if(amxdbg)
    {
      if (!clients.empty())
      {
        auto found = false;
        /* first search already found attached hook */
        for (auto& client : clients)
        {
          if (client && client->amx == amx)
          {
            found = true;
            client->DebugHook(amx);
            break;
          }
        }

          /* if not found, search for new client who wants to attach to current file */
        if (!found)
        {
          for (auto &client : clients)
          {
            for (int i = 0; i < amxdbg->hdr->files; i++) {
              for (auto file : client->files)
              {
                if (file.find(amxdbg->filetbl[i]->name) != std::string::npos)
                {
                  client->current_file = file;
                  client->DebugHook(amx);
                  break;
                }
              }
            }
          }
        } 
      }
    }
  }

  for(auto debug: debug_hooks)
  {
    if(debug.orig_amx == amx)
    {
      return debug.orig(amx);
    }
  }
}

void amx_dbgexec(AMX* amx, cell* retval, int index)
{
  Debugger* pDebugger = NULL;

  if (!amx || !(amx->flags & AMX_FLAG_DEBUG))
    return;
  pDebugger = (Debugger*)amx->userdata[UD_DEBUGGER];
  if (!pDebugger)
    return;
  if(!pDebugger->m_pAmxDbg)
  {
    return;
  }

  for(auto hook : debug_hooks)
  {
    if(hook.orig_amx == amx)
    {
      return;
    }
  }
  debug_hooks.push_back({ amx, amx->debug });
  amx->debug = AmxxDebug;
}
