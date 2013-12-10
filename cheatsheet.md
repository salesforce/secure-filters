
All of the filters in EJS syntax:

```html
  <style type="text/css">
    .userbox {
      background-color: #<%-: userColor |css%>;
    }
  </style>

  <script type="text/javascript>
    var config = <%-: config |jsObj%>;
    var userId = parseInt('<%-: userId |js%>',10);
  </script>

  <div style="border: 1px solid #<%-: userColor |style %>">
    <a href="/welcome/<%-: userId |uri%>">Welcome <%-: userName |html%></a>
    <a href="javascript:activate('<%-: userId |jsAttr%>')">Click here to activate</a>
  </div>
```
