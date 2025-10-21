# Zing
![2021082116344100-C2824459B66BC181AB3F3555311FDB2F](https://user-images.githubusercontent.com/68505331/130316347-40410f40-f96f-4a27-ae43-ee057cfef447.jpg)

A tesla overlay for game cheating. 
# Features 
## Monitor Game Memory and Cheat enable status
1. Show EdiZon SE bookmark value in game real time, show list of cheats enabled
![2021082116545100-C2824459B66BC181AB3F3555311FDB2F](https://user-images.githubusercontent.com/68505331/130316682-941e93df-807a-4e0f-9b57-972228ea7a94.jpg)



## Manage Cheats
2. Enable / disable cheats.
3. Organise cheats with outline labels
4. Assign multiplier value to increase the speed of gain of game items / attributes. 
5. Assign key press combo that activates or toggles cheats.
![2021082116445500-C2824459B66BC181AB3F3555311FDB2F](https://user-images.githubusercontent.com/68505331/130316786-8bf7b233-6439-400d-8797-220e86a23ff5.jpg)

# Installation
1. Install tesla overlay system from WerWolv. 
2. Place Breeze-Overlay.ovl in sdmc:/switch/.overlays/ 

# How to use
## Activate
1. Activate the overlay menu to select Zing. Start with the setting screen to select and config the cheating functions. Press ZL+B to move to monitor screen when you are done setting up Zing. You can toggle between Monitor and Settings by pressing ZL+B. When you press ZL+B from monitor screen the game will be frozen so you can do the setting at your leasure. Exiting setting screen will resume the game automatically. You can hide the monitor by pressing the tesla activation buttons. Press tesla activatoin buttons again to unhide the monitor.
## Navigate
2. Use Dpad, Right stick or Left stick for navigation. 
3. AnyUp and AnyDown moves the cursor up and down.
4. AnyLeft and AnyRight moves the cursor/change the mode in the a cycle: <- -> Bookmark <- -> Cheat outline <- -> Cheat List <- ->
5. When on Cheat List L and R either moves between outline group or inc dec the position by 20. Press X to toggle between these two modes.
6. When on Cheat outline pressing A jump to Cheat List and place the cursor on the first item of the outline group. AnyRight do the same thing.
## Key hints
5. Turn on key hints from the main menu or you can press ZL + to toggle it in "Settings".
## Assign muliplier to bookmark value
6. Navigate to the bookmark you want to set a multiplication on. Press L or R to adjust the value of the multiplier. 
7. This is useful for memory that holds item quantity or attribute value you want to tune the rate of gain.
## Edit memory value
9. Press A on the bookmark you want to edit the memory value. A minimalist keyboard will appear. Use AnyUp AnyDown to choose the value, L R to move the cursor position, A to enter and + to finish editing.
## Enable / Disable Cheats
19. Move cursor to cheat list item, press A to toggle.
## Assign button combos for cheats
20. Two kind of button combos are available. Button combo that is bind to the cheat code as conditional execute and button combos that trigger the overlay to toggle on/off the cheat code for button hold free enjoyment.
4. Rstick button / ZL + Rstick button program / remove conditional execute.
5. Lstick button / SL + Lstick button program / remove toggle. 

https://user-images.githubusercontent.com/68505331/129448517-4b318293-0405-4b9d-a3d0-f9aeae2de433.mp4










https://user-images.githubusercontent.com/68505331/129449230-ff923520-17f1-445e-b756-34a1e0338208.mp4


23. In this example the cheat code that moves the game character up and down is assigned to the stick up and stick down as conditional execute and the cheat code hover which makes the game character hover in the air is assign to button R which toggles the cheat on/off. The button combos that is bind to code is shown on the left of the cheat label and the code that toggles the cheat on / off is shown on the right of the cheat label. 
7. Some games make full use of every key so holding some key down is at times inconvenient and at other times not practical. There are also cases when most of the time you want the code enabled but occasionally you want to be able to quickly disable it. Moon Jump is very often going to prevent dropping down from platform. A quick way to disable moon jump is a good use case for this feature.

## Create bookmark from cheats
25. Some cheats can be use to create bookmark. Press + and if the cheat can be used to create bookmark a bookmark of the same name will be created.
## Creating outline
26. When first opcode is 0x2000000 the label is treated as a outline label.
## Reloading cheats
27. Everytime Zing is launched the cheats will be reloaded. 
28. There is also a button on the main menu to reload cheats. 
29. Using Zing there is no need to restart the game for update to cheat code to take effect. 
# Tips and Tricks
## Change cheat value
1. Some cheat value can be changed on the fly by adding from cheat to bookmark. 
2. After adding to bookmark the value can be edited.
# Known issue
1. Tesla takes up significant amount of memory. It is known for some time now that Tesla and EdiZon applet cannot be running at the same time with some games. The symptom is system freeze requiring long press of pwr button to recover. 
2. Dmnt is set to support only two session. This limit is enforced since atm19. Noexs(my fork) takes up one session. Zing will take one session. EdiZon SE or Breeze will take one session. That would be three so the last one will not be served. The solution is to pick the two you want to use. Exiting Zing (go back to tesla menu will release the session it takes). EdiZon SE or Breeze only takes a session when it is active. Noexs will take one if enabled. I recomment exiting Zing (go back to tesla menu) anyway as a good practice when you want to use any of the other three.
3. Don't unhide any overlay (not juse Zing) if you are making dump with Noexs.  
