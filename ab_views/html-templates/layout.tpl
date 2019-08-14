<!DOCTYPE html>
<html>
    <head>
        <title>{{block "title" .}}{{end}}</title>
        <link href="{{mountpathed "/static/main.css"}}" rel="stylesheet">
    </head>
    <body>
        {{block "authboss" .}}{{end}}
    </body>
</html>
