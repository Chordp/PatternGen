# -*- coding: utf-8 -*-
import math

import idaapi
import idc
#import clipboard

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            return idaapi.AST_DISABLE_FOR_FORM


    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1
except:
    pass

class PatternGen_Plugin_t(idaapi.plugin_t):
    comment = "Pattern Generate tool by:chord"
    help = "todo"
    wanted_name = "PatternGen"
    wanted_hotkey = "ALT+Z"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        try:
            print ("Pattern Generate tool by:chord")
            Searcher.register(self, "PatternGen")
        except:
            pass
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def printAvd(slef):
        print (25 * "===")

    def formatByte(self,ea):
        return " "+"{:02X}".format(idc.get_wide_byte(ea))

    def calcStr(self,ea, endcount):
        hstr = ""
        firstByte = self.formatByte(ea)
        hstr += self.formatByte(ea)
        hstr = hstr + self.formatByte(ea + 1) if (firstByte == "FF" or firstByte == "66" or firstByte == "67") else hstr
        #print(math.ceil(endcount - len(hstr) / 2))
        hstr = hstr + math.ceil(endcount - len(hstr) / 2) * " ??" if endcount >= 2 else hstr
        return hstr

    def extractCode(self):
        self.printAvd()

        start = idc.read_selection_start()
        end = idc.read_selection_end()
        codeSize = end - start
        ea = start
        # print hex(ea)
        result = ""

        for i in range(codeSize):
            op1 = idc.get_operand_type(ea, 0)
            op2 = idc.get_operand_type(ea, 1)
            instructionSize = idc.get_item_size(ea)

            if op1 == idc.o_reg and (op2 == idc.o_reg or op2 == idc.o_void or op2 == idc.o_phrase):
                for b in range(0, instructionSize):
                    result += self.formatByte(ea + b)
            elif (op1 == idc.o_reg and op2 == idc.o_displ) or (op1 == idc.o_displ and op2 == idc.o_reg) or (
                    op1 == idc.o_displ and op2 == idc.o_imm):
                result += self.formatByte(ea) + self.formatByte(ea + 1)
                for b in range(2, instructionSize):
                    result = result + " ??"
            elif op1 == idc.o_phrase and op2 == idc.o_reg:
                for b in range(0, instructionSize):
                    result += self.formatByte(ea + b)
            else:
                result += self.calcStr(ea, instructionSize)

            ea = ea + instructionSize
            if ea >= (start + codeSize):
                break
        # print (idc.get_event_module_base() -  idc.SelStart());
        print ("%s  Address:0x%x Offset:0x%x" % (idc.get_func_name(idc.here()),idc.here(), idc.here() - idaapi.get_imagebase()))
        # print result
        return result

    def run(self, arg):
        if (idc.BADADDR != idc.here()):
            copyContent = self.extractCode();
            print(copyContent)
            # clipboard.copy(copyContent)


# register IDA plugin
def PLUGIN_ENTRY():
    return PatternGen_Plugin_t();