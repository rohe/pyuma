<!DOCTYPE html>

<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" type="text/css" href="static/style.css" media="all"/>
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
    <div id="background"></div>
    <div class="container">
        <div class="page-header">
            <h1>Session info</h1>
        </div>
        <div class="result" class="block">
            <h2>Miscellanous information</h2>
            <table>
                % for key, val in info:
                    <tr>
                        <td><strong>${key}:</strong></td>
                        <td>${val}</td>
                    </tr>
                % endfor
            </table>
        </div>
        <hr>
        <div class="result" class="block">
            <h2>The complete assertion</h2>
            <pre>
                <code>
                    ${assertion}
                </code>
            </pre>
        </div>
    </div>
</body>
</html>