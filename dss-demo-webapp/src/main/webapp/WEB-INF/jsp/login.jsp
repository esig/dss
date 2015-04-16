<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<form action="j_security_check" method="post" id="login-form" role="form" class="form-horizontal">
    <div class="form-group">
        <label for="j_username" class="col-sm-2 control-label">Name</label> 
        <div class="col-sm-6">
            <input type="text" id="j_username" required name="j_username" class="form-control" />
        </div>
    </div>
    <div class="form-group">
        <label for="j_password" class="col-sm-2 control-label">Password</label>
        <div class="col-sm-6">
            <input type="password" id="j_password" name="j_password" class="form-control" />
        </div>
    </div>
    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-6">
            <button type="submit" class="btn btn-primary">Login</button>
        </div>
	</div>           
</form>

<div class="alert alert-info" role="alert" style="margin-top: 20px">
    Please see <a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/change-credentials-administration" class="alert-link">/wiki/change-credentials-administration</a> for
    information about how to change the password.
</div>
