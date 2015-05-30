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

namespace FS;


/**
 * Systém pro automatickou ochranu proti útokům na 
 * aplikaci. Umí ochránit proti XSS a SQL Injection
 * automaticky.
 * 
 * @version 1.0
 * @author Filip Šedivý
 * @copyright Copyright (c) 2013, Filip Šedivý
 */
class AttackProtect{
    
    
    /**
     * Ochrana vstupu
     */
    const Input = 'ProtectInput';
    
    
    /**
     * Ochrana SQL vstupu
     */
    const SQL = 'ProtectSQL';
    
    
    /**
     * Ochrana vstupu všemi technologie
     */
    const All = 'ProtectAll';
    
    
    /**
     * Vypne ochranu pro proměnnou
     */
    const PlainText = 'ProtectPlainText';
    
    
    /**
     * Globání pole hodnot
     * 
     * @static
     */
    private static $global;
    
    
    /**
     * Ochrana aplikace
     * 
     * @static
     * @param array $options Nastavení aplikace
     */
    public static function protect($options = array()){
        // Předání globálních proměnných do statických
        self::$global = array(
            'post' => $_POST,
            'get' => $_GET
        );
        
        // Iterace statických proměnných
        foreach(self::$global as $type => $globalValues){
            foreach($globalValues as $name => $value){
                $protection = array_key_exists($name, $options) ? $options[$name] : self::Input;
                if($type == 'get'){
                    $_GET[$name] = self::input($value, $protection);
                }elseif($type == 'post'){
                    $_POST[$name] = self::input($value, $protection);
                }
            }
        }
    }
    
    
    /**
     * Ochrana proměnné
     * 
     * @static
     * @param string $input Vstupní proměnná
     * @param AttackProtect::SQL|AttackProtect::Input|AttackProtect::PlainText|AttackProtect::All $type Typ ochrany
     * 
     * @return string Vrácený ochráněný vstup
     */
    protected static function input($input, $type){
        if($type == self::SQL){
            $search = array("\\",  "\x00", "\n",  "\r",  "'",  '"', "\x1a");
            $replace = array("\\\\","\\0","\\n", "\\r", "\'", '\"', "\\Z");
            return str_replace($search, $replace, $input);
        }elseif($type == self::Input){
            return htmlspecialchars($input);
        }elseif($type == self::PlainText){
            return $input;
        }elseif($type == self::All){
            $return = self::input($input, self::SQL);
            return self::input($return, self::Input);
        }
    }
    
}