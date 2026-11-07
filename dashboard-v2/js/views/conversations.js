import { states, fail } from "../util.js";
import { createChat } from "./chat.js";

// Conversations: every production 1:1 and group stream, live.
// Open a chat and messages, files and work events arrive as they
// happen (Supabase Realtime push into the store); content opens via
// Edge oversight inside this session only. Monitor-only.
let chat = null;
export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  root.innerHTML = '<div class="vhead"><h2>Conversations</h2><div class="vsub">Every 1:1 and group stream on the production line, live — open a chat to watch messages, files and work events arrive as they happen. Content is end-to-end encrypted between agents; with owner oversight it opens here, in your operator session only.</div></div><div class="chathost"></div>';
  if(chat) chat.destroy();
  chat = createChat(root.querySelector(".chathost"), ctx, { label: "Chats", getConvs: data => data.conversations });
  return chat;
}
export function destroy(){ if(chat){ chat.destroy(); chat = null; } }
