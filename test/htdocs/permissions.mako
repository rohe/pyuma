<!DOCTYPE html>

<%!

import urllib

def create_choice_tree(scopes, checked, action, entity_id, method, user, rsname):
    """
    Creates a tree of scope choices
    """

    desc_base = "http://its.umu.se/uma/attr"
    pattern = "<input type=\"checkbox\" name=\"perm\" value=\"%s\">%s<br>"
    chk_pattern = "<input type=\"checkbox\" name=\"perm\" value=\"%s\" checked>%s<br>"

    element = "<form action=\"%s\" method=\"%s\">" % (action, method)
    element += "<input type=\"hidden\" name=\"sp_entity_id\" value=\"%s\"/>" % entity_id
    element += "<input type=\"hidden\" name=\"user\" value=\"%s\"/>" % user
    element += "<input type=\"hidden\" name=\"rsname\" value=\"%s\"/>" % rsname
    element += "<table border=\"1\" border_color=\"black\">"
    scopes.sort()
    table = {"": {}}
    _all = False

    for scope in scopes:
        val = scope[len(desc_base):]
        if val == "":
            _all = True
            continue
        else:
            part = val.split("/")
            if len(part) < 3:
                continue
            _scope = "%s/%s" % (desc_base, part[1])
            try:
                table[""][(_scope, urllib.unquote(part[1]))].append(
                    (scope, urllib.unquote(part[2])))
            except KeyError:
                table[""][(_scope, urllib.unquote(part[1]))] = [
                    (scope, urllib.unquote(part[2]))]

    if _all:
        element += "<tr><td>"
        if desc_base in checked:
            element += chk_pattern % (desc_base, "All")
        else:
            element += pattern % (desc_base, "All")
        element += "</td><td></td>"
        element += "<td></td>"
        element += "</tr>"

    for key, vals in table[""].items():
        element += "<tr>"
        element += "<td></td><td>"
        if key[0] in checked:
            element += chk_pattern % (key[0], key[1])
        else:
            element += pattern % (key[0], key[1])
        element += "</td><td><ul>"
        for val in vals:
            if key[0] in checked:
                element += chk_pattern % (val[0], val[1])
            else:
                element += pattern % (val[0], val[1])
        element += "</ul></td>"
        element += "</tr>"

    element += "</table>"
    element += "<input type=\"submit\" name=\"commit\" value=\"permit\"/></form>"
    return element
%>

<html>
  <head>
    <title>pyoidc RP</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
    <script src="../../assets/js/html5shiv.js"></script>
    <script src="../../assets/js/respond.min.js"></script>
    <style type="text/css">
      tbody tr:nth-child(odd){ background-color:#ccc; }
    </style>
    <![endif]-->
  </head>
  <body>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h2>Chose the permissions: </h2>
        ${create_choice_tree(scopes, checked, action, entity_id, method, user, rsname)}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>