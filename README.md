node-winprocess
====================================

1. Introduction
---------------
This module provides functions to control windows processes. ReadProcessMemory WriteProcessMemory and DLL Injection

2. Example
---------------
	var winprocess = require('winprocess');
	
	var activeWindow = winprocess.getActiveWindowName();
	var pid = winprocess.getProcessId("notepad++.exe");	// or winprocess.getProcessIdByWindow("");

	var notepad = new winprocess.Process(pid);
	notepad.open();
	
	var baseAddress = notepad.getBaseAddress();
	
	var someAddress = 0x........
	notepad.writeMemory(someAddress, new Buffer([0x0]));
	var memBuffer = notepad.readMemory(someAddress, 3);
	
	var someOffset = 0x...
	var multiPtr = notepad.readMultiLevelPointerMemory(someAddress, someOffset, ...);
	
	notepad.inject("some.dll");
	
	setTimeout(function(){
		notepad.terminate();
		notepad.close();
	}, 1000);
