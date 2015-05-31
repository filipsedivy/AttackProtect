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
 * @copyright Copyright (c) 2013 - 2015, Filip Šedivý
 * @access public
 * @see http://filipsedivy.github.io/AttackProtect/
 */
class AttackProtect{
    
    
    /**
     * Ochrana vstupu
     * 
     * @var string
     */
    const Input = 'ProtectInput';
    
    
    /**
     * Ochrana SQL vstupu
     * 
     * @var string
     */
    const SQL = 'ProtectSQL';
    
    
    /**
     * Ochrana vstupu proti SQL Injection a XSS
     * 
     * @var string
     */
    const All = 'ProtectAll';
    
    
    /**
     * Vypne ochranu
     * 
     * @deprecated since version 1.1
     * @var string
     * @access public
     */
    const PlainText = 'ProtectPlainText';
    
    
    /**
     * Vypne ochranu
     * 
     * @var string
     */
    const Disable = 'ProtectDisable';
    
    
    /**
     * Přetypuje ochranu na číslo
     * 
     * @var string
     */
    const Number = 'ToNumber';
    
    
    /**
     * Globání pole hodnot
     * 
     * @static
     * @access protected
     */
    protected static $global;
    
    
    /**
     * Výchozí ochrana
     * 
     * @static
     * @access public
     */
    public static $defaultProtect = self::Input;
    
    
    /**
     * Ochrana aplikace
     * 
     * @static
     * @param array $options Nastavení aplikace
     * @access public
     */
    public static function protect($options = array()){
        // Předání globálních proměnných do statických
        self::$global = array(
            'post' => filter_input_array(INPUT_POST),
            'get' => filter_input_array(INPUT_GET)
        );
        
        // Iterace statických proměnných
        foreach(self::$global as $type => $globalValues){
            if(!is_null($globalValues)){
                foreach($globalValues as $name => $value){
                    $protection = array_key_exists($name, $options) ? $options[$name] : self::$defaultProtect;
                    $output = self::input($value, $protection);
                    if($type == 'get'){
                        $_GET[$name] = $output;
                    }elseif($type == 'post'){
                        $_POST[$name] = $output;
                    }
                }
            }
        }
    }
    
    
    /**
     * Ochrana proměnné
     * 
     * @static
     * @param string $input Vstupní text
     * @param mixed $option Nastavení
     * @access protected
     * 
     * @return string Vrácený ochráněný vstup
     */
    protected static function input($input, $option){
        if(is_string($option)){
            if($option == self::SQL){
                $search = array("\\",  "\x00", "\n",  "\r",  "'",  '"', "\x1a");
                $replace = array("\\\\","\\0","\\n", "\\r", "\'", '\"', "\\Z");
                return str_replace($search, $replace, $input);
            }elseif($option == self::Input){
                return htmlspecialchars($input);
            }elseif($option == self::PlainText || $option == self::Disable){
                return $input;
            }elseif($option == self::All){
                $return = self::input($input, self::SQL);
                return self::input($return, self::Input);
            }elseif($option == self::Number){
                if(filter_var($input, FILTER_VALIDATE_INT)){
                    return (int) $input;
                }elseif(filter_var($input, FILTER_VALIDATE_FLOAT)){
                    return (real) $input;
                }else{
                    return null;
                }
            }
        }elseif(is_array($option)){
            $return = $input;
            foreach($option as $key){
                $return = self::input($return, $key);
            }
            return $return;
        }
    }
}