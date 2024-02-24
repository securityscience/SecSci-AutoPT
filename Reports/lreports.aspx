<!-- -------------------------------------------- -->
<!--          Sec-Sci AutoPT | 2018-2023          -->
<!-- -------------------------------------------- -->
<!-- Site:      www.security-science.com          -->
<!-- Email:     RnD@security-science.com          -->
<!-- Creator:   Arnel C. Reyes                    -->
<!-- @license:  GNU GPL 3.0                       -->
<!-- @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM -->
<!-- -------------------------------------------- -->


<%@ Page Language="C#" Debug="false" ValidateRequest="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Web.Helpers" %>
<%
if (Request.Form["__RequestVerificationToken"] != null) {
  AntiForgery.Validate();
}
%>
<html>
<head>
<meta name="referrer" content="no-referrer">
<title>Sec-Sci AutoPT Reports</title>
<style>
  table, th, td { border: 1px solid black; border-collapse: collapse; font-family: Arial; font-size: 12px}
  th, td { padding: 3px; }
  body { font-family: Arial; color: #404042; background: #dedede; }
  .frmContainer label { font-size: 12px; font-weight: 500; }
  a:link, a:visited { text-decoration: none; transform: 0.3s; }
  a:hover, a:active { color: #e24920; text-decoration: underline; 
</style>
</head>
<body>
<center>
<table style="border: 0px;"><tr><td style="border: 0px;" valign="top"><img src="SecSciAutoPT_icon.png" width="25" height="25"></td>
                      <td style="border: 0px;" valign="center"> <b style="font-family: Arial; font-size: 18px;">Sec-Sci AutoPT Reports</b></td></tr></table>
<form action="lreports.aspx" method="post">
  <div class="frmContainer">
  <label>Project Name:</label>
  <input type="text" style="width: 120px;" name="projectName" value="" maxlength="18" />
  <input type="checkbox" name="chkArchive" value="Archived/"><label>Archived</label>
  <input type="submit" name="submit" value="Search" />
  <%=System.Web.Helpers.AntiForgery.GetHtml() %>
  </div>
</form>
<%
string chkArchive = Request.Form["chkArchive"];
string projectName = Request.Form["projectName"];
string webRootPath = Server.MapPath("/");

if (projectName == null) { projectName = ""; }
Regex pattern = new Regex("[/:*?\"<>|]");
projectName = pattern.Replace(projectName, "-");
projectName = projectName.Replace('\\', '-');

DirectoryInfo df;
if (chkArchive == "Archived/") { df=new DirectoryInfo(webRootPath + "\\Archived"); Response.Write("<b>Archived Sec-Sci AutoPT Reports</b><br><br>");}
else { df=new DirectoryInfo(webRootPath); }
%>
<table class="tblList">
<tr><td><b>Project Name</b></td><td><b>Burp File</b></td><td width="130"><b>Date & Time</b></td></tr>
<%
FileInfo[] fi=df.GetFiles("*" + projectName + "*.burp");

for(int i=0;i<fi.Length;i++) {

string s = fi[i].ToString();
string[] fn = s.Split('_');

Response.Write("<tr>");
Response.Write("<td><a href=\"" + chkArchive + s.Substring(0, s.Length - 5) + ".html\" target=\"reportView\">" + fn[0] + "</a></td>");
Response.Write("<td><a href=\"" + chkArchive + fi[i] + "\" target=\"_blank\">Download</a></td>");
Response.Write("<td>" + File.GetLastWriteTime(webRootPath + chkArchive + "\\" + fi[i]).ToString() + "</td>"); 
Response.Write("</tr>");
}
%>     
</table>
</center>
</body>
</html>
