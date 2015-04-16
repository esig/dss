<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<div class="loginbox">

    <form action="j_security_check" method="post" class="common-form" id="login-form">
        <fieldset>
            <legend class="hidden">Login</legend>
            <div style="width: 180px;">
                <label for="name">Name</label> <input type="text" id="j_username" required name="j_username" />
            </div>
            <div style="width: 180px;" class="clear">
                <label for="pass">Password</label> <input type="password" id="j_password" name="j_password" />
            </div>
            <div class="button-container">
                <input type="submit" class="button" value="Login" />
            </div>
        </fieldset>
    </form>

</div>

<div class="common-box">
    <p>
        Please see <a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/change-credentials-administration">/wiki/change-credentials-administration</a> for information about
        how to change the password.
    </p>
</div>
