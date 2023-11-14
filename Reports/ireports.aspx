<!-- -------------------------------------------- -->
<!--          Sec-Sci AutoPT | 2018-2023          -->
<!-- -------------------------------------------- -->
<!-- Site:      www.security-science.com          -->
<!-- Email:     RnD@security-science.com          -->
<!-- Creator:   Arnel C. Reyes                    -->
<!-- @license:  GNU GPL 3.0                       -->
<!-- @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM -->
<!-- -------------------------------------------- -->

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

<script>
  // Function to create and submit the form
  function sendParametersToIframe() {
    var iframeUrl = "lreports.aspx";
    var iframe = document.getElementById("lreportView");
    var projectName = getUrlParameter("projectName");

    // Create a form element
    var form = document.createElement("form");
    form.action = iframeUrl;
    form.method = "post";
    form.target = "lreportView";

    // Create an input field for the projectName parameter
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = "projectName";
    input.value = projectName;
    form.appendChild(input);

    // Append the form to the document body and submit it
    document.body.appendChild(form);
    form.submit();
  }

  // Function to get a specific URL parameter by name
  function getUrlParameter(name) {
    var urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
  }

  // Call the function when the page loads
  window.onload = sendParametersToIframe;
</script>

<center>
<table class="tlbFrame" width="100%" height="100%" border="0">
<tr>
  <td valign="top" align="center" width="400">
    <iframe name="lreportView" src="lreports.aspx" width="100%" height="100%"></iframe>
  </td>
  <td>
    <iframe name="reportView" src="SecSciAutoPT.htm" width="100%" height="100%"></iframe>
  </td>
</tr>
</table>
</center>
</body>
</html>