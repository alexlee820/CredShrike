"""Name pools for same-length pseudonyms (see credshrike/surrogate.py).

Deliberately small and bundled: the generator indexes these by string length,
so it can pick a real-looking replacement of exactly the original's length.
Lengths not covered here fall back to the syllable generator.

The lists are common given/family names and common Chinese name characters
(public-domain style lists). Duplicates are harmless — the index dedupes.
"""

FIRST_NAMES = """
Al Bo Ed Jo Ty Amy Ben Bob Dan Eve Guy Ian Jim Joe Max Mia Sam Tom Zoe Leo Ava
Anna Jack Liam Mark Mary Nick Paul Rose Ryan Sara Will Emma Noah Owen Ruby Alex Ella Luke John
Alice Amber Brian Chloe David Emily Grace Harry Jacob James Laura Linda Lucas Maria Mason Megan
Nancy Oscar Peter Sarah Steve Susan Wendy Helen Frank Clara Diego Laura Olive Hazel Irene
Amanda Angela Andrew Daniel Edward George Hannah Joshua Justin Karen Kevin Lauren Martin Nathan
Oliver Rachel Samuel Sophie Steven Thomas Victor Walter Yvonne Carlos Denise Louise Philip
Anthony Barbara Charles Dorothy Eleanor Jessica Jonathan Matthew Melissa Michael Natalie Patrick
Rebecca Richard Stephen Timothy William Vanessa Kenneth Cynthia Douglas Raymond Sharon Teresa
Benjamin Caroline Catherine Christina Danielle Elizabeth Jennifer Katherine Margaret Nicholas
Patricia Samantha Stephanie Victoria Alexander Frederick Gregory Jonathan Katherine Meredith
Charlotte Christian Gabrielle Alexandra Christopher Jacqueline Josephine Mackenzie Nathaniel
Sebastian Veronica Maximilian Montgomery Penelope Theodore Valentina Cassius Dominique Guillermo
Bartholomew Evangeline
""".split()

LAST_NAMES = """
Li Wu Ho Ye An Bo Du Fu Hu Lu Ma Mo Ni Ou Pan Qi Su Tan Yu
Lee Ray Kim Roy Fox Bell Cole Dean Ford Hall Hart King Lane Long Page Park Ross Shaw Ward Wood Young Gray Hill Hunt West
Adams Allen Baker Brown Clark Davis Evans Grant Green Hayes Jones Kelly Lewis Lynch Moore Morgan Murphy Price Smith Scott
Taylor Turner Walker White Wright Bailey Barnes Butler Carter Cooper Edwards Fisher Foster Gibson Graham Harris Howard
Hughes Jackson Martin Mitchell Parker Phillips Powell Roberts Robinson Russell Thomas Wallace Watson Anderson Bennett
Brooks Campbell Collins Crawford Ferguson Hamilton Harrison Jenkins Johnson Johnston Marshall Morrison Patterson Peterson
Sanders Simmons Stevens Sullivan Thompson Alexander Armstrong Atkinson Blackwood Caldwell Cameron Davidson Douglas
Fitzgerald Gallagher Harrington Henderson Livingston Mcdonald Mcpherson Nicholson Robertson Sinclair Williamson Beaumont
Cavendish Devonshire Ellington Fairbanks Gainsborough Kensington Lancaster Pennington Rockwell Somerville Wellington
Applegate Carmichael Fitzpatrick Vanderbilt Montague Pemberton Ashford Whitaker
""".split()

# Common Chinese surnames (single-character; enough variety for a few thousand runs)
CJK_SURNAMES = list("王李張劉陳楊黃趙吳周徐孫馬朱胡郭何高林羅鄭梁謝宋唐許韓馮鄧曹彭曾蕭田董袁潘于蔣蔡余杜葉程魏蘇呂丁任沈姚盧姜崔鍾譚陸汪范金石廖賈夏韋付方白鄒孟熊秦邱江尹薛閻段雷侯龍史陶黎賀顧毛郝龔邵萬錢嚴覃武戴莫孔向湯")

# Characters commonly used in given names (avoid ones that read as words)
CJK_GIVEN = list(
    "偉芳娜秀英敏靜麗強磊軍洋勇艷傑娟濤明超霞平剛桂華建國文輝玲蘭玉梅萍紅娥琳欣怡婷"
    "嘉俊浩宇軒梓涵雨晨思遠志宏海峰雲飛雪瑩曉春曉東建平志強麗娟秀蘭鳳英桂英玉蘭"
    "家豪子軒浩然一鳴天佑俊傑志明嘉欣美玲雅雯詩涵心怡芷若思穎"
)
