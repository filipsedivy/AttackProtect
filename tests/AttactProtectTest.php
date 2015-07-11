<?php

/* 
 * Copyright (C) 2013 - 2015, Filip Šedivý
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once '../src/AttackProtect.php';

use FS\AttackProtect;

class AttackProtectTest extends PHPUnit_Framework_TestCase{
    
    public function testDisable(){
        $this->assertEquals(
                'Hello World', 
                AttackProtect::_('Hello World', AttackProtect::Disable)
            );
    }
    
    public function testSQL(){
        $this->assertEquals(
                "SELECT \' FROM users",
                AttackProtect::_("SELECT ' FROM users", AttackProtect::SQL)
            );
    }
    
    public function testXSS(){
        $this->assertEquals(
                "&lt;b&gt;Hello &lt;span&gt;World&lt;/span&gt;&lt;/b&gt;",
                AttackProtect::_("<b>Hello <span>World</span></b>", AttackProtect::Input)
            );
    }
    
}