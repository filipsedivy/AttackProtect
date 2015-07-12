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
 * System for automatic protection against attacks on the 
 * application. It can protect against XSS and SQL Injection
 * automatically.
 * 
 * @version 1.0
 * @author Filip Sedivy
 * @copyright Copyright (c) 2013 - 2015, Filip Sedivy
 * @access public
 * @see http://filipsedivy.github.io/AttackProtect/
 */
class AttackProtect{
    
    
    /**
     * Protect input
     * 
     * @var string
     */
    const Input = 'ProtectInput';
    
    
    /**
     * Protect SQL input
     * 
     * @var string
     */
    const SQL = 'ProtectSQL';
    
    
    /**
     * Protect input against SQL Injection and XSS
     * 
     * @var string
     */
    const All = 'ProtectAll';
    
    
    /**
     * Disable protect
     * 
     * @deprecated since version 1.1
     * @var string
     * @access public
     */
    const PlainText = 'ProtectPlainText';
    
    
    /**
     * Disable protect
     * 
     * @var string
     */
    const Disable = 'ProtectDisable';
    
    
    /**
     * Cast protection on number 
     * 
     * @var string
     */
    const Number = 'ToNumber';
    
    
    /**
     * Global array values
     * 
     * @static
     * @access protected
     */
    protected static $global;
    
    
    /**
     * Default protection
     * 
     * @static
     * @access public
     */
    public static $defaultProtect = self::Input;
    
    
    /**
     * Appliaction protection
     * 
     * @static
     * @param array $options Setting appliaction
     * @access public
     */
    public static function protect($options = array()){
        // Transmission global variables to static
        self::$global = array(
            'post' => filter_input_array(INPUT_POST),
            'get' => filter_input_array(INPUT_GET)
        );
        
        // Iterating static variable
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
     * Protection input string
     * 
     * @static
     * @param string $input Input string
     * @param string|array $options Setting
     * @access public
     * 
     * @return string Protect string
     */
    public static function _($input, $options){
        return self::input($input, $options);
    }
    
    
    
    /**
     * Protect string
     * 
     * @static
     * @param string $input Input string
     * @param string|array $option Setting
     * @access protected
     * 
     * @return string Protect string
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