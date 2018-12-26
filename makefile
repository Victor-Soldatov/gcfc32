# Makefile : gcfc32
#            
# Usage:     NMAKE option
# option:    DEBUG=[0|1]
#            (DEBUG not defined => DEBUG=0)
#

#.PHONY: ALL CLEAN install uninstall
#.PHONY: ALL CLEAN

TARGET = gcfc32
MSGTBL = MsgTbl
OBJDIR = .\Obj32

!IF "$(DEBUG)" == "1"
TARGETDIR = .\Debug32
!ELSE
TARGETDIR = .\Release32
!ENDIF

CPP = "d:\Microsoft Visual Studio 10.0\VC\bin\cl.exe"
RSC = rc.exe
LINK = "d:\Microsoft Visual Studio 10.0\VC\bin\link.exe"
MC = mc.exe

LIB_PATH = "d:\Microsoft SDKs\Windows\v7.0\Lib"
INC_PATH = "d:\Microsoft SDKs\Windows\v7.0\Include"
RT_PATH = "d:\Microsoft Visual Studio 10.0\VC\include"

# /EHsc /nologo /MTd

!IF "$(DEBUG)" == "1"
CPP_PROJ = /c /MTd /I $(RT_PATH) /I $(INC_PATH) /Zi /W4 /WX- /Od /Oy- /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /Gm /RTC1 /GS /fp:precise /Zc:wchar_t /Zc:forScope /Fp"$(OBJDIR)\$(TARGET).pch" /Fa"$(TARGETDIR)" /Fo"$(OBJDIR)\$(TARGET).obj" /Fd"$(OBJDIR)\$(TARGET).pdb" /Gz /analyze- /errorReport:queue
LINK_FLAGS = /LIBPATH:$(LIB_PATH) /OUT:"$(TARGETDIR)\$(TARGET).exe" /MANIFEST /ManifestFile:".\$(MANIFEST)" /ALLOWISOLATION /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /DEBUG /PDB:"$(OBJDIR)\$(TARGET).pdb" /SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT /MACHINE:X86 /ERRORREPORT:QUEUE /VERBOSE /INCREMENTAL
!ELSE
CPP_PROJ = /c /MT /I $(RT_PATH) /I $(INC_PATH) /Zi /W4 /WX- /Ox /Oi /Oy- /GL /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /Gm- /EHsc /MT /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Fp"$(OBJDIR)\$(TARGET).pch" /Fa"$(TARGETDIR)" /Fo"$(OBJDIR)\$(TARGET).obj" /Fd"$(OBJDIR)\$(TARGET).pdb" /Gd /analyze- /errorReport:queue
LINK_FLAGS = /LIBPATH:$(LIB_PATH) /OUT:"$(TARGETDIR)\$(TARGET).exe" /VERSION:"1.0.0.1" /INCREMENTAL:NO /MANIFEST /ManifestFile:".\$(MANIFEST)" /ALLOWISOLATION /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /PDB:"$(OBJDIR)\$(TARGET).pdb" /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /LTCG /TLBID:1 /DYNAMICBASE /NXCOMPAT /MACHINE:X86 /ERRORREPORT:QUEUE /VERBOSE 
!ENDIF

RES_FLAGS = /I $(INC_PATH) /D "_UNICODE" /D "UNICODE" /l 0x409 /v /fo"$(OBJDIR)\$(RESFILE)" /x
MC_FLAGS = -u -U -v -z MsgTbl 

OBJS = gcfc32.obj
LIBS = kernel32.lib user32.lib
RESFILE = gcfc32.res
MANIFEST = gcfc32.manifest
MSGTBLRES = MsgTbl.rc
 
#	Instructions
#	ALL:
$(TARGETDIR)\$(TARGET).exe :: $(OBJDIR) $(TARGETDIR) $(OBJS)
	$(LINK) $(LINK_FLAGS) $(OBJDIR)\$(OBJS) $(LIBS) $(OBJDIR)\$(RESFILE) 

$(OBJS) :: $(TARGETDIR) $(OBJDIR) $(TARGET).cpp $(RESFILE)
	$(CPP) $(CPP_PROJ) $(TARGET).cpp

$(RESFILE):: $(TARGET).rc $(MSGTBLRES)
	$(RSC) $(RES_FLAGS) $(TARGET).rc 

$(MSGTBLRES):: $(TARGET).mc
	$(MC) $(MC_FLAGS) $(TARGET).mc

$(OBJDIR):
	if not exist "$(OBJDIR)" mkdir "$(OBJDIR)"

$(TARGETDIR):
	if not exist "$(TARGETDIR)" mkdir "$(TARGETDIR)"

CLEAN:
	erase /S /Q $(OBJDIR) $(TARGETDIR)
