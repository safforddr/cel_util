/* pcclient_verify.h
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * each content verifier must have fix, display, and verify functions
 */

void fix_pcclient_content(struct tlv *tlv);
void display_pcclient_content(struct tlv *tlv);
void verify_pcclient_content(struct record *r);


