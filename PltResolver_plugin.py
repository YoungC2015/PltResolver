# coding = gbk
# author: YoungC
# modified to IDA 7.5 with python 3.8
import idc
import idaapi
import idautils
import ida_ida

def SetFuncFlags(ea):
    func_flags=idc.get_func_attr(ea, FUNCATTR_FLAGS)
    func_flags|=0x84 # FUNC_THUNK|FUNC_LIB
    idc.set_func_attr(ea, FUNCATTR_FLAGS, func_flags)

def PltResolver64(debug_mode = False):
    def GetDyn():
        phoff = idc.get_qword(ida_ida.inf_get_min_ea()+0x20)+ida_ida.inf_get_min_ea()
        phnum = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x38)
        phentsize = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x36)
        for i in range(phnum):
            p_type = idc.get_wide_dword(phoff+phentsize*i)
            if p_type == 2: # PY_DYNAMIC
                dyn_addr = idc.get_qword(phoff+phentsize*i+0x10)
                return dyn_addr

    def ParseDyn(dyn,tag):
        idx=0
        while True:
            v1,v2 = idc.get_qword(dyn+idx*0x10),idc.get_qword(dyn+idx*0x10+8)
            if v1 == 0 and v2 == 0:
                return
            if v1 == tag:
                return v2
            idx+=1
    
    def __PltResolver(jmprel,strtab,symtab):
        idx=0
        while True:
            r_off = idc.get_qword(jmprel+0x18*idx)
            r_info1 = idc.get_wide_dword(jmprel+0x18*idx+0x8)
            r_info2 = idc.get_wide_dword(jmprel+0x18*idx+0xc)
            r_addend = idc.get_qword(jmprel+0x18*idx+0x10)
            if r_off > 0x7fffffff:
                return
            if r_info1 == 7:
                st_name = idc.get_wide_dword(symtab+r_info2*0x18)
                name = idc.get_strlit_contents(strtab+st_name)
                # rename got
                idc.set_name(r_off,name.decode("ascii") + '_ptr')
                plt_func = idc.get_qword(r_off)
                if debug_mode:
                    print(hex(plt_func.start_ea), name)
                # rename plt
                idc.set_name(plt_func,'j_' + name.decode("ascii"))
                SetFuncFlags(plt_func)
                # rename plt.sec
                for addr in idautils.DataRefsTo(r_off):
                    plt_sec_func = idaapi.get_func(addr)
                    if plt_sec_func:
                        plt_sec_func_addr = plt_sec_func.start_ea
                        idc.set_name(plt_sec_func_addr,'_' + name.decode("ascii"))
                        SetFuncFlags(plt_sec_func_addr)
                    else:
                        print("[!] idaapi.get_func({}) failed".format(hex(addr)))
            idx+=1
        
    dyn = GetDyn()
    if not dyn:
        print("[-] can't find symbol '_DYNAMIC'")
        return
    jmprel = ParseDyn(dyn,0x17)
    strtab = ParseDyn(dyn,0x5)
    symtab = ParseDyn(dyn,0x6)
    if not jmprel:
        print("[-] can't find 'DT_JMPREL' in '_DYNAMIC'")
        return
    if not strtab:
        print("[-] can't find 'DT_STRTAB' in '_DYNAMIC'")
        return
    if not symtab:
        print("[-] can't find 'DT_SYMTAB' in '_DYNAMIC'")
        return
    __PltResolver(jmprel,strtab,symtab)

def PltResolver32(debug_mode = False):
    def GetDyn():
        phoff = idc.get_wide_dword(ida_ida.inf_get_min_ea()+0x1c)+ida_ida.inf_get_min_ea()
        phnum = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x2c)
        phentsize = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x2a)
        for i in range(phnum):
            p_type = idc.get_wide_dword(phoff+phentsize*i)
            if p_type == 2: # PY_DYNAMIC
                dyn_addr = idc.get_wide_dword(phoff+phentsize*i+8)
                return dyn_addr

    def ParseDyn(dyn,tag):
        idx=0
        while True:
            v1,v2 = idc.get_wide_dword(dyn+idx*0x8),idc.get_wide_dword(dyn+idx*0x8+4)
            if v1 == 0 and v2 == 0:
                return
            if v1 == tag:
                return v2
            idx+=1

    def __PltResolver(jmprel,strtab,symtab,pltgot):
        seg_sec = idc.selector_by_name('.plt.sec')
        sec_start = idc.get_segm_by_sel(seg_sec)
        sec_end = idc.get_segm_end(sec_start)
        if sec_start == idaapi.BADADDR:
            print("[-] can't find .plt.sec segment")
            return
        idx=0
        while True:
            r_off = idc.get_wide_dword(jmprel+0x8*idx)
            r_info1 = idc.get_wide_byte(jmprel+0x8*idx+0x4)
            r_info2 = idc.get_wide_byte(jmprel+0x8*idx+0x5)
            if r_off > 0x7fffffff:
                return
            if r_info1 == 7:
                st_name = idc.get_wide_dword(symtab+r_info2*0x10)
                name = idc.get_strlit_contents(strtab+st_name)
                # rename got
                idc.set_name(r_off,name.decode("ascii") + '_ptr')
                plt_func = idc.get_wide_dword(r_off)
                # rename plt
                idc.set_name(plt_func,'j_' + name.decode("ascii"))
                SetFuncFlags(plt_func)
                # rename plt.sec
                for addr in idautils.DataRefsTo(r_off):
                    plt_sec_func = idaapi.get_func(addr)
                    if plt_sec_func:
                        plt_sec_func_addr = plt_sec_func.start_ea
                        idc.set_name(plt_sec_func_addr,'_' + name.decode("ascii"))
                        SetFuncFlags(plt_sec_func_addr)
                    else:
                        print("[!] idaapi.get_func({}) failed".format(hex(addr)))
                got_off = r_off-pltgot
                target = '+{}h'.format(hex(got_off).lower().replace('0x','').replace('l','').rjust(2,'0'))
                for func_ea in idautils.Functions(sec_start,sec_end):
                    func = idaapi.get_func(func_ea)
                    cur = func.start_ea
                    end = func.endEA
                    find=False
                    while cur <= end:
                        code = idc.GetDisasm(cur).lower().replace(' ','')
                        if target in code:
                            find=True
                            break
                        cur = idc.NextHead(cur, end)
                    if find:
                        idc.set_name(func_ea,'_'+name)
                        SetFuncFlags(func_ea)
            idx+=1

    dyn = GetDyn()
    if not dyn:
        print("[-] can't find symbol '_DYNAMIC'")
        return
    jmprel = ParseDyn(dyn,0x17)
    strtab = ParseDyn(dyn,0x5)
    symtab = ParseDyn(dyn,0x6)
    pltgot = ParseDyn(dyn,0x3)
    if not jmprel:
        print("[-] can't find 'DT_JMPREL' in '_DYNAMIC'")
        return
    if not strtab:
        print("[-] can't find 'DT_STRTAB' in '_DYNAMIC'")
        return
    if not symtab:
        print("[-] can't find 'DT_SYMTAB' in '_DYNAMIC'")
        return
    if not pltgot:
        print("[-] can't find 'DT_PLTGOT' in '_DYNAMIC'")
        return
    __PltResolver(jmprel,strtab,symtab,pltgot)

class PltResolver_handler(idaapi.action_handler_t):
    def __init__(self, debug_mode = False):
        idaapi.action_handler_t.__init__(self)
        self.debug_mode = debug_mode

    def activate(self, ctx):
        print(ctx)
        arch = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x12)
        if arch == 0x3E: # EM_X86_64
            PltResolver64(self.debug_mode)
        elif arch == 0x3: # EM_386
            PltResolver32(self.debug_mode)
        else:
            print('[-] Only support EM_X86_64 and EM_386')
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PltResolver_old(idaapi.plugin_t): # 留着查API
    flags = idaapi.PLUGIN_HIDE
    comment = 'pltResolver'
    help = ''
    wanted_name = 'pltResolver'
    wanted_hotkey = ''

    def init(self):
        idaapi.msg('===================================================\n')
        idaapi.msg('pltResolver plugin has been loaded.\n')
        idaapi.msg('Press Ctrl+Shift+J to resolve .plt.sec symbols.\n')
        idaapi.msg('===================================================\n')

        idaapi.register_action(idaapi.action_desc_t('pltResolver:pltResolver', 'Parse .plt.sec symbols', PltResolver_handler(), 'Ctrl+Shift+J', None, 25))#注册action
        idaapi.attach_action_to_menu('Edit/pltResolver', 'pltResolver:pltResolver', idaapi.SETMENU_APP)#将action添加到menu

        return idaapi.PLUGIN_KEEP

    def term(self):#析构
        idaapi.unregister_action('pltResolver:pltResolver')

    def run(self,arg):
        pass

class PltResolver(idaapi.plugin_t): 
    flags = idaapi.PLUGIN_UNL
    comment = 'resolve plt function name by plt_sec'
    help = ''
    wanted_name = 'PltResolver'
    wanted_hotkey = ''

    def init(self):
        idaapi.msg("=======================\nPltResolver loadeed.\n")
        #idaapi.register_action(idaapi.action_desc_t('pltResolver:pltResolver', 'Parse .plt.sec symbols', PltResolver_handler(), 'Ctrl+Shift+J', None, 25))#注册action
        #idaapi.attach_action_to_menu('Edit/pltResolver', 'pltResolver:pltResolver', idaapi.SETMENU_APP)#将action添加到menu
        return idaapi.PLUGIN_OK

    def term(self):#析构
        pass

    def run(self, arg):
        arch = idc.get_wide_word(ida_ida.inf_get_min_ea()+0x12)
        if arch == 0x3E: # EM_X86_64
            PltResolver64()
        elif arch == 0x3: # EM_386
            PltResolver32()
        else:
            print('[-] Only support EM_X86_64 and EM_386')
        return 1

def PLUGIN_ENTRY():
    return PltResolver()


if __name__ == "__main__":
    pr_handler = PltResolver_handler(True)
    pr_handler.activate(0)