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
                <h1>Federation Authentication Information</h1>
                <h2>Attributes</h2>
            </div>
            <div class="result" class="block">
                <p>
                   These attributes were send from the Identity Provider (${idp}).
                    <br>
                   The 'eduPersonPrincipalName' attribute if present is often used as a permanent identifier for you.
                </p>
                % if uinfo:
                    <table border='1'>
                        % for attr, val in uinfo:
                            <tr>
                                <td>${attr}</td>
                                <td>${val}</td>
                            </tr>
                        % endfor
                    </table>
                % else:
                    <p><b>No indentity information was returned</b></p>
                % endif
            </div>
            <div>
                <ul>
                    <li><a href=${session}>Session information</a></li>
                </ul>
            </div>
        </div>
    </body>
</html>