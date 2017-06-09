 <html>
 <head>
  
    <link rel="stylesheet" href="http://cdn.bootcss.com/bootstrap/3.3.4/css/bootstrap.min.css"> 
    <script src="/js/jquery-3.2.1.min.js"></script> 
    <script src="http://cdn.bootcss.com/bootstrap/3.3.4/js/bootstrap.min.js"></script>
    <title>Security Auth</title> 
 </head>
<body>
<div class="container">

    <div class="header clearfix">
        <nav>
            <ul class="nav nav-pills pull-right">
            </ul>
        </nav>
        <h3 class="text-muted">CS Auth Server</h3>
    </div> 

    <div class="row marketing">
        <div class="col-lg-10">
             <form class="form-horizontal" method="post" action="/user/redirectPageLogin"> 
  
                <input type="hidden" name="authRedirectUrl" value="${(authRedirectUrl)!}">
                
                <div class="form-group">
                    <label for="username" class="col-sm-4 control-label">User Id</label>
                    <div class="col-sm-8">
                        <input type="text" class="form-control" id="_OAUTH2_USER_ID" name="userId" placeholder="User Id">
                    </div>
                </div>
                <div class="form-group">
                    <label for="password" class="col-sm-4 control-label">Password</label>
                    <div class="col-sm-8">
                        <input type="password" class="form-control" id="_OAUTH2_USER_PWD" name="userPwd" placeholder="Password">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-offset-4 col-sm-8">
                        <button type="submit" class="btn btn-default" name="#tnLogin">Login</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
<footer class="footer">
    <p>&copy; Company 2015</p>
</footer>

</div> <!-- /container -->
</body>
</html>