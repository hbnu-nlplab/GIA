========================================
MODEL: candidate_answer
========================================

Total Questions : 10000
Correct Answers : 6744
Wrong Answers   : 3256

- Mismatch     : 2989
- Parse Error  : 267 (형식 불일치)

----------------------------------------

Accuracy        : 67.44%
========================================

[Parse Error 상세 (267개)]
============================================================

1. Idx: 80
   Question: The Hamiltonian can be interpreted as the ________...
   Gold    : option 3: energy
   LLM     : I’m sorry, but I can’t provide that passage.

------------------------------------------------------------
1. Idx: 106
   Question: What is the name of the 3GPP standard for low cost...
   Gold    : option 5: eMTC
   LLM     : eMTC

------------------------------------------------------------
1. Idx: 113
   Question: What is a limitation of Global Navigation Satellit...
   Gold    : option 3: Suffer from shadowing introduced by foliage and obstacles
   LLM     : No answer can be determined from the given information.

------------------------------------------------------------
1. Idx: 142
   Question: What is the main cause of attenuation in glass fib...
   Gold    : option 2: Material absorption
   LLM     : The passage does not provide the answer.

------------------------------------------------------------
1. Idx: 150
   Question: Which entity controls the packet duplication funct...
   Gold    : option 4: MgNB
   LLM     : The passage provided does not contain any statement about which entity controls packet duplication in dual connectivity.

------------------------------------------------------------
1. Idx: 155
   Question: What is the role of Wireless Backhaul in mobile tr...
   Gold    : option 2: To support massive capacity demand
   LLM     : NOT FOUND

------------------------------------------------------------
1. Idx: 185
   Question: What is the purpose of the UE Capability Managemen...
   Gold    : option 4: All of the above
   LLM     : unknown

------------------------------------------------------------
1. Idx: 211
   Question: What does the home environment need to provide to ...
   Gold    : option 3: Subscription data
   LLM     : The correct answer is not provided in the text.

------------------------------------------------------------
1. Idx: 273
   Question: What is the main challenge faced by network operat...
   Gold    : option 2: High backhaul usage
   LLM     : The passage does not specify which challenge is main.

------------------------------------------------------------
1. Idx: 318
   Question: What protocol is used for transferring email betwe...
   Gold    : option 5: SMTP
   LLM     : The Simple Mail Transfer Protocol (SMTP) is used for transferring email between mail servers.

------------------------------------------------------------

[오답 예시 (상위 5개)]
============================================================

1. Idx: 7
   Question: Why does an originator regularly send a BlockAckRe...
   Gold    : option 4: To minimize buffering latency at the receivers
   LLM     : option 2: To request acknowledgment from the group members

------------------------------------------------------------
1. Idx: 16
   Question: What are the primary neural network architectures ...
   Gold    : option 1: Unsupervised pre-trained networks, convolutional neural networks, and recursive neural networks
   LLM     : option 3: Unsupervised pre-trained networks, convolutional neural networks, and recurrent neural networks

------------------------------------------------------------
1. Idx: 17
   Question: What is the Laplace transform or the PGF used for?...
   Gold    : option 3: Determining the probability generating function of distributions
   LLM     : option 1: Determining the mean, variance, and coefficient of variation

------------------------------------------------------------
1. Idx: 19
   Question: What is the purpose of the PSFCH channel in NR V2X...
   Gold    : option 2: To transmit HARQ feedback for unicast and groupcast
   LLM     : option 5: To transmit resource allocation configurations

------------------------------------------------------------
1. Idx: 23
   Question: What is an advantage of lower frequency (sub-GHz) ...
   Gold    : option 2: Lower frequency has wider coverage
   LLM     : option 5: Lower frequency enables non-LOS imaging

------------------------------------------------------------
