#Enumerate each function of the program and print their Pcode from Disassembly in less verbose mode
	 
#@author Yash Kumar
#@category CodeAnalysis
#@keybinding 
#@menupath 
#@toolbar Edit

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
	#print stri
	return stri
	

#f = getGlobalFunctions("Java_com_xmp_MainActivity_fun1")[0]
#print "[+]Name of the Function: ",f.getName()
#print "[+]Starting Address of the Function: ", f.getEntryPoint()
#print "...."

#hf = get_high_function(f)
#dump_refined_pcode(f,hf)

def allfunctions():
	f_nameArr = []
	f_entrypointArr = [] 
	
	state = getState()
	currentProgram = state.getCurrentProgram()
	name = currentProgram.getName()
	location = currentProgram.getExecutablePath()
	print("[+] The currently loaded program is: '{}'".format(name))
	print("[+] Location on disk is: '{}'".format(location))


	f = getFirstFunction()
	while f is not None:
		 
		#print "[+]Function: ", f.getName()
		f_nameArr.append(f.getName())
	
		#print "[+]Function EntryPoint: ", f.getEntryPoint()
		f_entrypointArr.append(f.getEntryPoint())	
			
		hf = get_high_function(f)
		f_pcode = dump_refined_pcode(f,hf)   	
		func_data.append(f_pcode)		

		f = getFunctionAfter(f)

	f_namestr = [str(x) for x in f_nameArr]
	 
	#print f_namestr  #List of Functions
	#print func_data[8]  #List of Function P-code

	#print type(f_entrypointArr)  #List of Function EntryPoint
	z = {}
	z = dict(zip(f_namestr, f_pcode))

	zz = {}
	# using dictionary comprehension
	# to convert lists to dictionary
	zz = {f_namestr[i]: func_data[i] for i in range(len(f_namestr))}

	#~~~~~~JSON File~~~~~~
	os.chdir('C:\\users\\boyka\\ghidra_scripts')
	try: 
		with open('data0007.json', 'a') as f_json: 			
			f_json.write(json.dumps(zz))
			print "[+] File saved at Location: ", os.getcwd() 
	except:	
			print "[-] File Operation Error X X X"

	for p in range(0,len(f_namestr)): 
		
		if f_namestr[p] == 'foo': 
			print "[x] Native Function Found!!!" 
			print p
			print f_namestr[p]
			print func_data[p][0] + func_data[p][1] + func_data[p][2] + func_data[p][3]

		else: 
			pass

allfunctions() 




