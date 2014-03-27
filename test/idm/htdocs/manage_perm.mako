<%!
def resource_set_choice(rs_list):
    """
    Creates a dropdown list of resource sets
    Each item in the list is a tuple of (resource set name, resource id)
    """
    element = "<select name=\"resource\">"
    for name, rsid in rs_list:
        element += "<option value=\"%s\">%s</option>" % (rsid, name)
    element += "</select>"
    return element
%>

<%!
def trusted_services(perm_list):
    """
    Creates a table of service, approval date, permissions
    Each item in perm_list is a dictionary of (name, perm_dict)
    """
    element = "<select name=\"requestor\">"
    for name, entity_id in rs_list:
        element += "<option value=\"%s\">%s</option>" % (entity_id, name)
    element += "</select>"
    return element
%>

<html>
  <head>
    <title>UMA AS manage page</title>
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
        <form action="${action}" method="${method}">
            <input type="hidden" name="user" value="${user}">
            <h3>Manage Permissions</h3>
            <h4>Trusted services</h4>
            You can manage permission to your identity by services.
            <hr>

            <br>
            <input type="submit" name="commit" value="display"/>
            <input type="submit" name="commit" value="modify"/>
            <input type="submit" name="commit" value="add"/>
            <input type="submit" name="commit" value="delete"/>
            a permission
        </form>
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>