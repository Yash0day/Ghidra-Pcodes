#TODO write a description for this script
#@author Yash Kumar
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import os, json
import csv

func_data = []
stri = []

def get_high_function(func):
	options = DecompileOptions()
	monitor = ConsoleTaskMonitor()
	ifc = DecompInterface()
	ifc.setOptions(options)
	ifc.openProgram(getCurrentProgram())
        
	res = ifc.decompileFunction(func, 60, monitor)
	high = res.getHighFunction()
	return high
        
def dump_refined_pcode(func, high_func):
	stri = []
	opiter = high_func.getPcodeOps()
	
	while opiter.hasNext():
		
		op = opiter.next()
		stri.append(str(op))
        

	func_data.append(stri)
	print "------------------"
	print func_data
	return func_data
	

f = getGlobalFunctions("yash")[0]
print "[+]Name of the Function: ",f.getName()
print "[+]Starting Address of the Function: ", f.getEntryPoint()


hf = get_high_function(f)
dump_refined_pcode(f,hf)