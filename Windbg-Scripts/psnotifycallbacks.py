from pykd import *

version = getSystemVersion()

def ptr_size():
  if is64bitSystem():
  	return 8
  else:
  	return 4

def checkKernelDebugging():
  if not isKernelDebugging() and not isLocalKernelDebuggerEnabled():
    print("[-] Not running inside KD!")
    exit(1)

# load required module 'nt'
def loadNT():
  try:
    nt = module("nt")
  except: 
    print("[-] Couldn't not get the base address of 'ntoskrnl'.")
    exit(1)
  return nt

def fastref(_EX_FAST_REF):
  return ((_EX_FAST_REF >> 4) << 4)

def listCallbacks(CallbacksArray, ArraySize):
  PSIZE = ptr_size()
  for i in range(ArraySize):
    callback = (CallbacksArray + (i * PSIZE))
    try:
      callback = ptrPtr(callback)
    except:
      print i
      print ArraySize
      print("[-] Couldn't read memory!!")
      exit(1)
    if callback == 0:
      continue
    obj = fastref(callback)

    try:
	  apicall = ptrPtr(obj + (PSIZE))
    except:
      print("[-] Couldn't read memory!")
      exit(1)

    print("[{}] {:#x} ({})".format(i, apicall, findSymbol(apicall)))

def processCallbacks(nt):
  try:
    PspCreateProcessNotifyRoutineExCount = ptrDWord(nt.offset("PspCreateProcessNotifyRoutineExCount"))
    PspCreateProcessNotifyRoutineCount  = ptrDWord(nt.offset("PspCreateProcessNotifyRoutineCount"))
    PspCreateProcessNotifyRoutine = nt.offset("PspCreateProcessNotifyRoutine")
  except:
  	print("[-] Couldn't not read memory and/or load Symbols")
  	exit(1)

  if version.buildNumber <= 3790:
  	num = PspCreateProcessNotifyRoutineCount
  else:
    num = PspCreateProcessNotifyRoutineExCount + PspCreateProcessNotifyRoutineCount
  print("[+] Total of: {} CreateProcessNotifyRoutines".format(num))
  listCallbacks(PspCreateProcessNotifyRoutine, num)

def threadCallbacks(nt):
  try:
    PspCreateThreadNotifyRoutineCount = ptrDWord(nt.offset("PspCreateThreadNotifyRoutineCount"))
    PspCreateThreadNotifyRoutine = nt.offset("PspCreateThreadNotifyRoutine")
  except:
    print("[-] Couldn't not read memory and/or load Symbols")
    exit(1)

  if version.buildNumber >= 10240:
  	num = PspCreateThreadNotifyRoutineCount + ptrDWord(nt.offset("PspCreateThreadNotifyRoutineNonSystemCount"))
  else:
    num = PspCreateThreadNotifyRoutineCount
  print("\n[+] Total of: {} CreateThreadNotifyRoutines".format(num))
  listCallbacks(PspCreateThreadNotifyRoutine, num)

def loadimageCallbacks(nt):
  try:
    PspLoadImageNotifyRoutineCount = ptrDWord(nt.offset("PspLoadImageNotifyRoutineCount"))
    PspLoadImageNotifyRoutine = nt.offset("PspLoadImageNotifyRoutine")
  except:
    print("[-] Couldn't not read memory and/or load Symbols")
    exit(1)

  num = PspLoadImageNotifyRoutineCount
  print("\n[+] Total of: {} CreateLoadImageRoutines".format(num))
  listCallbacks(PspLoadImageNotifyRoutine, num)

if __name__ == '__main__':
  checkKernelDebugging()
  nt = loadNT()
  processCallbacks(nt)
  threadCallbacks(nt)
  loadimageCallbacks(nt)
