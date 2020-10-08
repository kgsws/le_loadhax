.section .text
.global hook_malloc
.global hook_free
.global hook_realloc
.global hook_I_SetPalette
.global hook_I_GetTime
.global hook_I_ZoneBase
.global handle_input
.global D_PostEvent
.global hook_I_StartSound
.global hook_I_SoundIsPlaying
.global hook_I_UpdateSoundParams
.global hook_I_StopSound

.global hook_W_CacheLumpNum_enter
.global hook_W_CacheLumpNum_leave

hook_malloc:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp

	push	%eax
	call	malloc
	add	$4,%esp

	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_free:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp

	push	%eax
	call	free
	add	$4,%esp

	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_realloc:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp

	push	%edx
	push	%eax
	call	realloc
	add	$8,%esp

	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_I_SetPalette:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp

	push	%eax
	call	I_SetPalette
	add	$4,%esp

	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_I_GetTime:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp

	call	SDL_GetTicks
	mov	$35,%ebx
	mul	%ebx
	mov	$1000,%ebx
	div	%ebx

	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_I_ZoneBase:
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp
	mov	$0x02000000,%ebx
	mov	%ebx,(%eax)
	push	%ebx
	call	I_ZoneBase
	add	$4,%esp
	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	ret

handle_input:
	pusha
	call	sdl_input
	popa
	ret

D_PostEvent:
	mov	4(%esp),%eax
	jmp	*doom_D_PostEvent

hook_I_StartSound:
	push	%esi
	push	%ebp
	push	%ecx
	push	%ebx
	push	%edx
	push	%eax
	call	I_StartSound
	add	$16,%esp
	pop	%ebp
	pop	%esi
	ret	$0x8

hook_I_SoundIsPlaying:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp
	push	%eax
	call	I_SoundIsPlaying
	add	$4,%esp
	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

hook_I_UpdateSoundParams:
	push	%esi
	push	%edi
	push	%ebp
	push	%edx
	push	%ebx
	push	%eax
	call	I_UpdateSoundParams
	add	$12,%esp
	pop	%ebp
	pop	%edi
	pop	%esi
	ret

hook_I_StopSound:
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi
	push	%ebp
	push	%eax
	call	I_StopSound
	add	$4,%esp
	pop	%ebp
	pop	%edi
	pop	%esi
	pop	%edx
	pop	%ecx
	pop	%ebx
	ret

/*
hook_W_CacheLumpNum_enter:
	mov	%eax,(ex_cache_lump_num)
	push	%ebx
	push	%ecx
	push	%esi
	push	%edi
	mov	%eax,%ecx
	jmp	*doom_W_CacheLumpNum

hook_W_CacheLumpNum_leave:
	push	%edx
	push	%eax
	call	W_CacheLumpNum
	pop	%eax
	pop	%edx
	pop	%edi
	pop	%esi
	pop	%ecx
	pop	%ebx
	ret
*/

