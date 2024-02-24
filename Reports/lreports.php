<html>
<head>
    <meta name="referrer" content="no-referrer">
    <title>Sec-Sci AutoPT Reports</title>
    <style>
        table, th, td {
            border: 1px solid black;
            border-collapse: collapse;
            font-family: Arial;
            font-size: 12px
        }

        th, td {
            padding: 3px;
        }

        body {
            font-family: Arial;
            color: #404042;
            background: #dedede;
        }

        .frmContainer label {
            font-size: 12px;
            font-weight: 500;
        }

        a:link, a:visited {
            text-decoration: none;
            transform: 0.3s;
        }

        a:hover, a:active {
            color: #e24920;
            text-decoration: underline;
        }
    </style>
</head>
<body>
<center>
    <table style="border: 0px;">
        <tr>
            <td style="border: 0px;" valign="top"><img src="SecSciAutoPT_icon.png" width="25" height="25"></td>
            <td style="border: 0px;" valign="center"> <b style="font-family: Arial; font-size: 18px;">Sec-Sci AutoPT Reports</b></td>
        </tr>
    </table>
    <form action="lreports.php" method="post">
        <div class="frmContainer">
            <label>Project Name:</label>
            <input type="text" style="width: 120px;" name="projectName" value="" maxlength="18"/>
            <input type="checkbox" name="chkArchive" value="Archived/"><label>Archived</label>
            <input type="submit" name="submit" value="Search"/>
        </div>
    </form>
    <?php
    $chkArchive = isset($_POST["chkArchive"]) ? $_POST["chkArchive"] : "";
    $projectName = isset($_POST["projectName"]) ? $_POST["projectName"] : "";
    $webRootPath = $_SERVER["DOCUMENT_ROOT"];

    if ($projectName === null) {
        $projectName = "";
    }
    $pattern = "/[\/:*?\"<>|]/";
    $projectName = preg_replace($pattern, "-", $projectName);
    $projectName = str_replace('\\', '-', $projectName);

    if ($chkArchive === "Archived/") {
        $df = scandir($webRootPath . "/Archived");
        echo "<b>Archived Sec-Sci AutoPT Reports</b><br><br>";
    } else {
        $df = scandir($webRootPath);
    }
	
	$df = array_diff($df, array('.', '..'));
    ?>
    <table class="tblList">
        <tr>
            <td><b>Project Name</b></td>
            <td><b>Burp File</b></td>
            <td width="130"><b>Date & Time</b></td>
        </tr>
        <?php
		
		$fi = preg_grep("/$projectName.*\.burp$/i", $df);

        foreach ($fi as $f) {
            $fn = explode("_", $f);

            echo "<tr>";
            echo "<td><a href=\"" . $chkArchive . substr($f, 0, -5) . ".html\" target=\"reportView\">" . $fn[0] . "</a>
            echo "<td><a href=\"" . $chkArchive . $f . "\" target=\"_blank\">Download</a></td>";
            echo "<td>" . date("Y-m-d H:i:s", filemtime($webRootPath . "/" . $chkArchive . "/" . $f)) . "</td>";
            echo "</tr>";
        }
        ?>
    </table>
</center>
</body>
</html>
