node-winprocess
====================================

1. Introduction
---------------
This module provides functions to control windows processes. ReadProcessMemory WriteProcessMemory and DLL Injection

2. Example
---------------
	var winprocess = require('winprocess');
	
	setInterval(function(){
		console.log(winprocess.getActiveWindowName());
	}, 333);
	
	var pid = winprocess.getProcessId("notepad++.exe");
	var notepad = new winprocess.Process(pid);
	var address = 0x076F97C0;
	
	var testBuffer = new Buffer("SWT");
	notepad.open();
	notepad.writeMemory(address, testBuffer);
	var memory = notepad.readMemory(address, 3);
	console.log(testBuffer.equals(memory)?"PASS":"FAIL");
	notepad.close();
	

