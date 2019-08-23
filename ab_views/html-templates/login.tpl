<div class="fullPage">
    <div class="contentWrap">
        <img src="{{mountpathed "static/logo-neg.png"}}" alt="Nearby Computing logo" />
        <form class="loginForm" action="{{mountpathed "login"}}" method="POST">
            {{with .error}}{{.}}<br />{{end}}
            <input class="input" type="text" class="form-control" name="email" placeholder="E-mail" value="{{.primaryIDValue}}"><br />
            <input class="input" type="password" class="form-control" name="password" placeholder="Password"><br />
            {{with .csrf_token}}<input type="hidden" name="csrf_token" value="{{.}}" />{{end}}
            {{with .challenge}}<input type="hidden" name="challenge" value="{{.}}" />{{end}}
            <div class="loginRow">
                {{with .modules}}{{with .remember}}
                    <label class="rememberMe">
                        <input type="checkbox" name="rm" value="true" checked> Remember Me</input>
                    </label>
                {{end}}{{end -}}
                {{with .redir}}<input type="hidden" name="redir" value="{{.}}" />{{end}}
                <button class="login" type="submit">Login</button>
            </div>
            {{with .modules}}{{with .recover}}<br /><a href="{{mountpathed "recover"}}">Recover Account</a>{{end}}{{end -}}
            {{with .modules}}{{with .register}}<br /><a href="{{mountpathed "register"}}">Register Account</a>{{end}}{{end -}}
        </form>
    </div>
</div>
