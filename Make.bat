call egcc.bat

:: build library
gcc %CCFLAGS2% *.cpp -c
copy /Y traceMe.h %PROGRAMS%\local\include
ar -rcs  %PROGRAMS%\local\lib32\libexshit.a *.o

:: build test
gcc test.cc %CCFLAGS2% -lexshit -lstdshit -ludis86 -o test.exe
del *.o
