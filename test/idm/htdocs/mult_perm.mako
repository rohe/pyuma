<!DOCTYPE html>

<%!

import urllib

def _key_sort(k1, k2):
    if k1[1] == k2[1]:
        return 0
    elif k1[1] > k2[1]:
        return 1
    else:
        return -1

def create_choice_tree(tree, checked, action, entity_id, method, rsname,
                       user=""):
    """
    Creates a tree of resource choices"
    The given tree is of the form {("alice", rsid1):{("email", rsid2): [
        ("foo@bar", rsid3), ("xyz@com", rsid4)]}}
    checked is of the form [rsid1, rsid2]
    """

    pattern = "<input type=\"checkbox\" name=\"perm\" value=\"%s\">%s<br>"
    chk_pattern = "<input type=\"checkbox\" name=\"perm\" value=\"%s\" checked>%s<br>"

    element = "<form action=\"%s\" method=\"%s\">" % (action, method)
    element += "<input type=\"hidden\" name=\"sp_entity_id\" value=\"%s\"/>" % entity_id
    if user:
        element += "<input type=\"hidden\" name=\"user\" value=\"%s\"/>" % user
    element += "<input type=\"hidden\" name=\"rsname\" value=\"%s\"/>" % rsname
    element += "<table border=\"1\" border_color=\"black\">"

    element += "<tr><td>"
    _rsid1, _base = tree.keys()[0]
    if _rsid1 in checked:
        element += chk_pattern % (_rsid1, "All")
    else:
        element += pattern % (_rsid1, "All")
    element += "</td><td></td>"
    element += "<td></td>"
    element += "</tr>"

    _keys = tree[tree.keys()[0]].keys()
    _keys.sort(_key_sort)
    _dic = tree[tree.keys()[0]]

    for key in _keys:
        vals = _dic[key]
        (rsid2, _id) = key
        element += "<tr>"
        element += "<td></td><td>"
        if rsid2 in checked:
            element += chk_pattern % (rsid2, urllib.unquote(_id))
        else:
            element += pattern % (rsid2, urllib.unquote(_id))
        element += "</td><td><ul>"
        for val in vals:
            (rsid3, _val) = val
            if rsid3 in checked:
                element += chk_pattern % (rsid3, urllib.unquote(_val))
            else:
                element += pattern % (rsid3, urllib.unquote(_val))
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
        <h2>Chose which attributes or attribute values you want to release: </h2>
        ${create_choice_tree(scopes, checked, action, entity_id, method, rsname, user)}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>