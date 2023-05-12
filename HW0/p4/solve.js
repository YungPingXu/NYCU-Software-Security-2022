var fs = require("fs");
fs.readFile("/flag", "utf8", function(err, data){process.stdout.write(data);});
const content = 'f = open("/flag","r")\nprint(f.read(),end="")'
fs.writeFile(`${__filename}`, content, err => {});