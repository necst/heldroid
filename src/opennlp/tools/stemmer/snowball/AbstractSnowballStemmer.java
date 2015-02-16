/*
2	
3	Copyright (c) 2001, Dr Martin Porter
4	Copyright (c) 2002, Richard Boulton
5	All rights reserved.
6	
7	Redistribution and use in source and binary forms, with or without
8	modification, are permitted provided that the following conditions are met:
9	
10	    * Redistributions of source code must retain the above copyright notice,
11	    * this list of conditions and the following disclaimer.
12	    * Redistributions in binary form must reproduce the above copyright
13	    * notice, this list of conditions and the following disclaimer in the
14	    * documentation and/or other materials provided with the distribution.
15	    * Neither the name of the copyright holders nor the names of its contributors
16	    * may be used to endorse or promote products derived from this software
17	    * without specific prior written permission.
18	
19	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
20	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
21	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
22	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
23	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
24	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
25	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
26	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
27	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
28	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
29	
30	 */

package opennlp.tools.stemmer.snowball;

abstract class AbstractSnowballStemmer extends SnowballProgram {
    public abstract boolean stem();
};