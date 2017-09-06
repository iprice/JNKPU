/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.coagulate.JNKPU;

/** Represents a non terminal exception with the unlock.
 * Specifically, encapsulates all errors that cause us to be unable to process an unlock request, but that are not fatal and do not require us to terminate.
 * @author Iain Price
 */
public class UnlockException extends Exception {

    UnlockException(String message, Throwable cause) { super(message,cause); }
    UnlockException(String message) { super(message); }
}
