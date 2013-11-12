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
                <h1>IdP Testing</h1>
            </div>
            <ul>
                % for name, url in dslist.items():
                    <li><a href=${url}>Logga in via ${name}</a></li>
                % endfor
            </ul>
        </div>
    </body>
</html>