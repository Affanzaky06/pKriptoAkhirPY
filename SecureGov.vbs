Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\Kuliah\IF\Semester 5\Kriptografi\pKriptoAkhirPY"
WshShell.Run "pythonw.exe app.py", 0, False

