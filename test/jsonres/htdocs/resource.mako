<!DOCTYPE html>

<html>
  <head>
    <title>Choose the Resource Service</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
      <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="../../assets/js/html5shiv.js"></script>
      <script src="../../assets/js/respond.min.js"></script>
    <![endif]-->
  </head>
  <body>
    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h1>Choose the resource</h1>
        <p>
            The source is accessed by resource host, resource owner and resource name
        </p>
        <form class="form-signin" action="action" method="post">
            <input type="text" id="host" name="host" class="form-control" autofocus>
            <input type="text" id="owner" name="owner" class="form-control" autofocus>
            <input type="text" id="name" name="name" class="form-control" autofocus>
            <hr>
            What do you want to do with it ?
            <br>
            <input type="submit" name="commit" value="display"/>
            <input type="submit" name="commit" value="modify"/>
            <input type="submit" name="commit" value="add"/>
            <input type="submit" name="commit" value="delete"/>
        </form>
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>
  </body>
</html>