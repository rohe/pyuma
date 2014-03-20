<!DOCTYPE html>

<html>
  <head>
    <title>Authorization Service Choice</title>
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
        <h1>Choose Authorization Service</h1>
        <p>
            You need to instantiate a connection between this Resource Server and your Authorization Service.
            <br>
            This is where you choose which Authorization Service (AS) to use.
            <br>
            You have to provide the unique identifier that you have at the AS.
        </p>
        <form class="form-signin" action="rp" method="get">
            <h2 class="form-signin-heading">Start sign in flow</h2>
            <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>
        </form>
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>


  </body>
</html>